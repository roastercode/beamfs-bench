# beamfs-bench multifs/cluster - architecture revisee 2026-05-04

Document de cadrage pour la refonte de l'architecture de test
sous attaque RadFI. Produit suite a la R19 sub-5 du 2026-05-04
(manifest 20260504T145919Z) qui a expose un biais methodologique
dans le verdict actuel.

Ce document fait reference a la R19 sub-5 GPG-signee, n'invente
aucun chiffre. Toute citation factuelle est tracable au tarball
beamfs-bench-analyse-full-20260504-165540 sha256
69af1a3947fb1bc664da03627485f82d3f5824fa366067d8364bee819ce9b50f.

---

## 1. Probleme observe

Le test multifs head-to-head et le scope cluster emettent
actuellement le verdict VERIFIED/RECOVERED a partir d'une seule
mesure : cat TARGET puis sha256sum. Une fois le fichier en
pagecache, les bit-flips suivants tombent ailleurs sur le device
(metadonnees d'autres fichiers, root inode, blocks bitmap), pas
sur les data du fichier observe. Tous les FS sortent VERIFIED
indistinctement, y compris ceux qui n'offrent aucune protection.

Mesures factuelles observees (R19 sub-5, prob=1M, 4 nodes
cluster + 5 FS USB) :

| FS       | flips@1k | flips@100k | flips@1M | DIFFS pre/post |
|----------|----------|------------|----------|----------------|
| ext4     | 0        | 0          | 15       | 0              |
| ext3     | 0        | 17         | 111      | 0              |
| btrfs    | 0        | 0          | 3        | 0              |
| squashfs | 0        | 2          | 13       | 0              |
| beamfs   | 0        | 2          | 8        | 0              |

ext4 a recu 15 flips et sort DIFFS=0. ext4 n offre aucun mecanisme
de correction. La seule explication coherente est que les flips ne
tombent pas sur le fichier observe, ou tombent dessus mais l octet
qui a flip n est pas re-lu apres l attaque (le pagecache sert le
contenu pre-attaque). Le verdict actuel ne discrimine pas les FS.

Conclusion : conserver les 5 FS (decision Aurelien 2026-05-04
17:08) impose de reparer la methodologie avant de prendre toute
decision sur le set de FS comparatifs.

---

## 2. Proprietes que la nouvelle architecture doit garantir

### P1. Le contenu lu doit venir du disque, pas du cache.

Sans flush du pagecache et du icache entre l attaque et la
verification, les flips n ont aucun effet observable sur l octet
mesure. Le mecanisme : umount apres write/fsync force le flush du
icache et le writeback du pagecache. drop_caches 3 (defensif)
nettoie residuels. mount qui suit force la VFS a relire SB, root
inode, inode du fichier cible (via iget), data blocks (via
read_folio). Chaque lecture passe par submit_bio donc par le hook
RadFI.

### P2. L attaque doit cibler les blocs effectivement utilises par le fichier observe.

Avec target_block=0 (toute la surface), la fraction de flips qui
tombent sur les data du fichier cible est faible. Pour beamfs avec
file-B2.bin de 3 KB sur volume de 1 GB, ratio = 3 KB / 1 GB =
3e-6. Sur 8 flips injectes a prob=1M (beamfs), esperance = 8 * 3e-6
= 2.4e-5 flip sur le fichier cible. Statistiquement aucun.

Solution : pre-calcul de la liste des blocs physiques du fichier
(via filefrag ou equivalent par FS), puis configuration de RadFI
pour ne flipper que sur ces blocs. Necessite une nouvelle interface
RadFI : target_block_list, ou iteration sur target_block avec
plusieurs blocks successifs.

### P3. La detection doit etre proportionnelle a la corruption.

Verdict binaire (DIFFS=0 ou DIFFS!=0) ne distingue pas
"0 flip injecte" de "N flips parfaitement corriges". Il faut une
mesure quantitative : nombre de bits differents entre fichier
pre-attaque et fichier post-attaque (cmp -l ou popcount XOR), plus
une lecture structuree de dmesg post-mount pour compter les
corrections RS reelles.

---

## 3. Architecture en 6 composants

### Composant C1 - Cycle write/sync/umount/attack/mount/read

Refactor de worker action bench2_attack_FS (ou ajout d une
nouvelle action) pour passer du cycle actuel au cycle suivant :

  write 12 fichiers + fsync + close
  read pre-attack hashes (peuple cache, hash de reference)
  drop_caches 3
  umount
  RadFI enabled=Y, configure cible (cf C2)
  mount
  cat TARGET vers post.bin
  hash_post = sha256(post.bin)
  cmp -l file_pre.bin post.bin (compte bits differents)
  read dmesg post-mount
  RadFI enabled=N
  read flip_count delta
  emit verdict 5-classes (cf C3) + metriques (cf C4)

Pour squashfs (read-only) : pas de write/fsync, mkfs squashfs avec
contenu pre-genere, le reste du cycle s applique.

Effort : environ 3h. Pas de modification kernel. Pas de
modification RadFI. Patch worker + synthesis cote bench.

### Composant C2 - target_block_list dans RadFI

Modification de radfi (kernel module) pour accepter une liste de
blocs cibles plutot qu un seul. Trois variantes possibles :

(a) Nouvelle entree debugfs target_block_list (string avec liste
    "12,13,14,42") parsee a chaque ecriture.
(b) Iteration externe dans worker : pour chaque bloc dans la
    liste, programmer target_block, lancer un read sur ce bloc,
    incrementer.
(c) Hook bio elargi pour accepter un bitmap de blocs (range plus
    fin que target_block, plus eligible que target_block=0).

Variante (a) preferee : minimise les invocations debugfs, semantique
claire, lisible dans les forensics.

Pre-calcul de la liste cote bench :

  filefrag -v TARGET sur ext2/ext3/ext4 retourne la liste
    physical block start..end
  btrfs : btrfs filesystem show + extent tree (plus complexe)
  squashfs : tableau de tables compresse, pas de mapping direct,
    cibler le data block du target file via inode + block_size
  beamfs : pas de filefrag, mais inode contient direct[12] +
    indirect ; lecture du raw inode via debugfs si dispo,
    sinon dump SB + table pour calculer

Pour la premiere iteration : implementer pour ext4 + beamfs (les
deux qui ont une introspection facile), commencer par ces deux FS,
etendre aux autres apres validation.

Effort : environ 6-8h. Modification radfi (kernel module + ebuild
bump 0.1.3 vers 0.1.4) + worker helpers.

### Composant C3 - Verdict 5-classes

Le scope multifs emet deja des modes (RS_PASSTHROUGH observe sur
beamfs en R19 sub-5). Le scope cluster ne les emet pas (ref commit
a91db41 du log beamfs-bench : "cluster scope still emits factual
records but does not yet apply the RS_RECOVERED|RS_PASSTHROUGH|...
derivation"). Cette regle est uniformisee :

| Verdict        | Condition                                                    |
|----------------|--------------------------------------------------------------|
| RS_RECOVERED   | flips_inject > 0 AND hash_post == hash_pre AND dmesg shows N corrections >= 1 |
| RS_PASSTHROUGH | flips_inject == 0 AND hash_post == hash_pre                  |
| RS_FAILED      | flips_inject > 0 AND (mount fail OR hash_post != hash_pre AND dmesg shows uncorrectable) |
| FS_PANIC       | dmesg contains BUG/Oops/WARN OR mount fail with stack trace  |
| CORRUPTED_DATA | flips_inject > 0 AND hash_post != hash_pre AND dmesg shows no error |

Le cas CORRUPTED_DATA est crucial : c est ce qui distingue
empiriquement beamfs (qui devrait sortir RS_RECOVERED) d ext4 (qui
sortira CORRUPTED_DATA face a une attaque ciblee data block). Sans
ce verdict, on ne peut pas produire la figure principale du paper
v3.

Effort : environ 2h. Modification synthesis cote beamfs-bench.

### Composant C4 - Mesure de la corruption introduite

Plutot qu un binaire hash_pre == hash_post, calculer pour chaque
run :

  bits_differents = popcount(file_pre XOR file_post) byte par byte
  fraction_corrompue = bits_differents / total_bits
  distance_de_Hamming par bloc (= nombre de blocs avec >= 1 bit flip)

Implementation : cmp -l file_pre file_post produit la liste des
offsets octets differents avec leur valeur. Parser cette sortie en
Rust pour compter les bits flips reels.

Sortie : trois colonnes additionnelles dans cluster-records.txt et
multifs-all-records.txt :

  BITS_DIFF=N      total bits flips entre pre et post
  FRAC_CORRUPT=X.X fraction (en pourcentage)
  HAMM_BLOCKS=N    nombre de blocs avec au moins un bit flip

Donne une metrique continue plottable sur prob en X. beamfs avec RS
fonctionnel : plat a 0 jusqu au seuil de saturation RS. ext4 : monte
lineairement avec prob.

Effort : environ 1h. Helper Rust qui parse cmp -l, integration dans
synthesis.

### Composant C5 - N runs par point de mesure

Une seule mesure par (FS, prob) est statistiquement faible. RadFI
est probabiliste : meme prob donne 0 flip sur un run et 30 sur
l autre. Les seeds observes en R19 sub-5 (seed 11838571006... pour
master, 253145163... pour compute01) confirment que la seed est
deja randomisee, donc deux runs avec meme prob donnent deux
distributions differentes.

Pour avoir une distribution exploitable :

  N=5 minimum par (FS, prob)
  agregation : mediane, p25, p75 de la fraction_corrompue
  ecrit en JSON pour plotter dans le paper

N=10 ideal mais multiplie le temps de R19 par 10/3 = 3.3x. N=5 est
le compromis qui donne des p25/p75 grossiers tout en restant sous
les 30 minutes par R19 complet.

Effort : environ 2h. Boucle dans worker + agregation Rust.

### Composant C6 - Calibration de l attaque

Le test actuel a deux problemes lies :

  prob=1k donne souvent 0 flip (R19 sub-5 : 0 flip sur 4 nodes
    cluster + 5 FS USB = 9 mesures avec 0 flip a prob=1k)
  prob=1M donne 8 (beamfs) a 111 (ext3) flips selon le FS, pas de
    calibration commune

Comparer "RS_RECOVERED@2flips_pour_btrfs" et
"RS_RECOVERED@111flips_pour_ext3" est inequitable : ext3 a ete bien
plus attaque que btrfs.

Solution : calibrer prob pour viser un budget de flips fixe. Par
exemple, viser 10 flips effectifs par run :

  Run de calibration : prob=test_prob, count_reads, mesurer
    flips effectifs
  Ajuster effective_prob = test_prob * 10 / flips_observes
  Run de mesure avec effective_prob

L ordre s effectue par FS car le nombre de reads (donc d occasions
de flip) varie : ext4 fait 15 reads pour le scenario test, ext3 en
fait 111, btrfs 3. La calibration produit un effective_prob
specifique a chaque FS qui amene tous les FS au meme budget de
flips effectifs.

Effort : environ 3h. Run de calibration + ajustement prob, soit
manuel via une option --calibrate-budget=N, soit automatique en
deux passes.

---

## 4. Caveat methodologique sur le set de 5 FS

Le maintien des 5 FS (ext4, ext3, btrfs, squashfs, beamfs) est
explicitement valide par Aurelien 2026-05-04 17:08. Cette section
documente les rationale conceptuels par FS, non pas pour proposer
une reduction, mais pour cadrer l interpretation du paper v3 :

  ext4 : baseline mainline, journaling, FS de reference Linux ;
    sans correction d erreurs ; doit sortir CORRUPTED_DATA face a
    une attaque ciblee data ; ligne de comparaison directe.
  ext3 : architecture journaling identique a ext4 sans extents ;
    valeur scientifique additionnelle limitee mais permet de
    montrer que le journaling seul ne protege pas.
  btrfs : self-healing via checksum + RAID, le seul autre FS
    mainline qui pretend faire de l integrite de donnees ;
    comparaison directe sur la promesse "integrite de donnees".
  squashfs : read-only compresse ; categorie de produit
    differente ; sa presence dans le test illustre que les FS RO
    ne sont pas une reponse a la corruption silencieuse.
  beamfs : sujet du test, RS-FEC INLINE actif sur scheme=2.

Le paper v3 doit cadrer cette comparaison comme une matrice
"protection effective vs categorie de FS", pas comme un benchmark
de performance.

---

## 5. Ordre d execution propose

L architecture est decomposee en 3 milestones, chacun se cloturant
sur un R19 vert intermediaire commit-able.

### Milestone M1 (~5h) : verite forensique

  C1 : cycle umount/mount avec drop_caches
  C3 : verdict 5-classes uniforme cluster + multifs
  C4 : metriques bits_diff / frac_corrupt / hamm_blocks

A la cloture M1 : R19 vert avec verdicts qui peuvent etre
RS_PASSTHROUGH (cas attendu : pas de flip cible) sur tous les FS,
metriques continues emises mais probablement toutes a 0 (pas de
flip cible). C est la non-regression de l instrumentation.

### Milestone M2 (~6-8h) : attaque ciblee

  C2 : target_block_list dans RadFI + filefrag dans worker
  RadFI bump 0.1.3 vers 0.1.4
  beamfs-bench bump 0.4.2 vers 0.5.0 (changement architectural)

A la cloture M2 : R19 vert avec verdicts CORRUPTED_DATA pour ext4 /
ext3 / squashfs face a une attaque ciblee, RS_RECOVERED pour
beamfs, indetermine pour btrfs (depend de la nature de la cible).

### Milestone M3 (~5h) : statistiques exploitables

  C5 : N=5 runs par point
  C6 : calibration budget de flips
  Aggregation JSON pour figure paper v3

A la cloture M3 : R19 long (environ 30 minutes par scope avec N=5),
output JSON exploitable pour la figure principale du paper v3
(courbe fraction_corrompue vs prob, par FS).

---

## 6. Risques identifies

R1 - Modification RadFI casse les tests existants. Mitigation :
target_block_list est ajout, target_block reste compatible.
Default target_block_list=vide, default target_block=0, comportement
inchange si rien n est configure. R19 baseline doit rester vert
apres bump 0.1.3 vers 0.1.4.

R2 - filefrag indisponible dans l image canonique. Mitigation :
verifier IMAGE_INSTALL de hpc-arm64-research-beamfs (R23) avant
M2. Si absent, ajouter e2fsprogs filefrag au recipe.

R3 - N=5 runs allonge R19 a 30+ min. Mitigation : N est
parametrable via --runs-per-point, default N=1 pour preserver le
temps R19 actuel ; le R19 long n est invoque que pour la figure
paper, pas comme regression baseline.

R4 - target_block_list pour btrfs/squashfs non trivial. Mitigation :
M2 livre ext4 + beamfs en premier (les deux FS faciles), btrfs et
squashfs viennent en M2.5 si scientifiquement utile, sinon
documente comme non-cible (cible aleatoire = baseline conservateur).

R5 - CORRUPTED_DATA depend de la finesse du target_block_list.
Mitigation : verifier post-M2 que ext4 sort bien CORRUPTED_DATA
(non RS_FAILED qui suggererait une detection ext4 inexistante).
Si non, raffiner target_block_list pour cibler exactement les
blocks data (pas les blocks meta).

---

## 7. Definition of Done

Cloture func-12 sub-5 (au-dela de R19 sub-5 deja green) :

  Verdict CORRUPTED_DATA empiriquement observe pour ext4 sur
    attaque ciblee, dans un manifest GPG-signe.
  Verdict RS_RECOVERED empiriquement observe pour beamfs sur
    attaque ciblee, avec dmesg "corrected by RS FEC" >= 1, dans le
    meme manifest.
  Difference quantitative entre frac_corrompue ext4 et
    frac_corrompue beamfs sur trois ordres de grandeur de prob.
  Manifest reproductible par un tiers (R36 tarball + procedure
    documentee dans Documentation/testing).

C est ce manifest qui justifie la presence de PER_INODE_RS dans
v5.0 RFC mainline.
