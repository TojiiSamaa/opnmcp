# osmcp

Serveur [MCP](https://modelcontextprotocol.io) pour les pare-feu [OPNsense](https://opnsense.org) : il permet à un agent IA de consulter et de modifier un pare-feu par son API, avec des garde-fous.

- **Un outil par demande**, regroupés par domaine : `opn_list_firewall_rules`, `opn_add_firewall_rule`, `opn_toggle_firewall_rule`… Pas d'outil fourre-tout du type `firewall_manage(action, params)`.
- **Lecture seule par défaut.** Sans `OPNSENSE_ALLOW_WRITES=true`, les outils d'écriture ne sont même pas proposés.
- **Vrai rollback sur OPNsense 26.7 et plus**, version qui a supprimé le minuteur natif (voir [ci-dessous](#modifications-du-pare-feu), avec ses limites).
- **Détection du risque de blocage** : avant chaque application, le jeu de règles est évalué hors ligne pour vérifier que ce serveur atteindra encore le pare-feu.
- **Politique d'accès au plus près du réseau** : tout passe par un seul point de contrôle dans le client HTTP. Un outil annoncé en lecture seule ne peut pas envoyer d'écriture, quel que soit le chemin demandé.

> **État du projet.** Les tests tournent contre un faux serveur écrit d'après le code PHP d'OPNsense, pas contre un vrai pare-feu. Commencez avec une clé API en lecture seule, et gardez un accès console lors des premières écritures.

> ### Cette branche ajoute une version Rust (`rust/`) : mêmes 209 outils, un seul binaire
>
> ![Banc TypeScript contre Rust](bench/chart.svg)
>
> Les chiffres ci-dessus se mettent à jour tout seuls : le workflow `perf-bench` récupère chaque jour le code de Yuto, teste le TypeScript et le Rust, vérifie que les 209 outils restent identiques, puis redessine le graphe. [Détails et résultats](#version-rust-rust).

## Installation

Il faut Node.js 20.10 ou plus récent.

```bash
npm install
npm run build
```

Créez une clé API dans OPNsense (**System > Access > Users**, puis l'icône de clé sur l'utilisateur). Le fichier `apikey.txt` téléchargé peut être utilisé tel quel.

### Claude Code ou Claude Desktop

```json
{
  "mcpServers": {
    "opnsense": {
      "command": "node",
      "args": ["C:/chemin/vers/osmcp/dist/index.js"],
      "env": {
        "OPNSENSE_URL": "https://192.168.1.1",
        "OPNSENSE_API_CREDENTIALS_FILE": "C:/chemin/vers/apikey.txt",
        "OPNSENSE_CA_FILE": "C:/chemin/vers/opnsense-ca.pem"
      }
    }
  }
}
```

OPNsense utilise par défaut un certificat auto-signé. Il vaut mieux exporter son autorité et l'indiquer avec `OPNSENSE_CA_FILE`, ce qui garde la vérification active. `OPNSENSE_VERIFY_SSL=false` fonctionne aussi, mais à réserver à un réseau de confiance.

Vous trouverez un exemple dans [`examples/mcp.json`](examples/mcp.json).

## Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| `OPNSENSE_URL` | | Adresse du pare-feu |
| `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET` | | Identifiants de l'API |
| `OPNSENSE_API_CREDENTIALS_FILE` | | Ou le fichier `apikey.txt` |
| `OPNSENSE_ALLOW_WRITES` | `false` | Autorise les modifications |
| `OPNSENSE_DRY_RUN` | `false` | Propose les outils d'écriture, mais n'envoie rien : montre ce qui serait envoyé |
| `OPNSENSE_ALLOW_SENSITIVE` | `false` | Autorise les exports bruts et `include_sensitive` |
| `OPNSENSE_TOOLSETS` | tout sauf `haproxy` | Domaines à charger, ou `all` |
| `OPNSENSE_ROLLBACK_SECONDS` | `120` | Délai avant le retour arrière automatique (30 à 3600) |
| `OPNSENSE_MANAGEMENT_SOURCE` | détectée | Adresse vue par le pare-feu, si un NAT ou un VPN la masque |
| `OPNSENSE_VERIFY_SSL` | `true` | Vérification du certificat |
| `OPNSENSE_CA_FILE` | | Autorité à laquelle faire confiance |
| `OPNSENSE_TIMEOUT_SECONDS` | `30` | Délai d'attente des requêtes |
| `OPNSENSE_ELICIT` | `true` | Demande une confirmation humaine avant une action destructive, si le client sait le faire |
| `OPNSENSE_AUDIT_LOG` | | Fichier JSONL qui journalise les écritures et les refus |
| `OPNSENSE_UNBLOCK` | | Points d'API à retirer de la liste de blocage, séparés par des virgules |
| `OPNSENSE_MAX_RESPONSE_CHARS` | `120000` | Taille maximale d'une réponse |
| `OPNSENSE_CONFIG` | | Fichier décrivant plusieurs pare-feu |

Une faute de frappe dans une option de sécurité (`OPNSENSE_ALLOW_WRITES=ture`) arrête le serveur plutôt que d'appliquer une valeur par défaut.

### Plusieurs pare-feu

`OPNSENSE_CONFIG` pointe vers un fichier comme [`examples/instances.json`](examples/instances.json). Les valeurs `${VARIABLE}` sont lues dans l'environnement, ce qui évite d'y écrire les secrets. Chaque outil reçoit alors un paramètre `instance`, et les droits se règlent par pare-feu.

### Privilèges de la clé API

Le plus sûr est de créer un utilisateur dédié, avec seulement les privilèges des domaines utilisés (**System > Access > Groups**). Un privilège manquant donne une erreur `forbidden` qui l'indique clairement. `opn_security_audit` signale les sections qu'il n'a pas pu lire au lieu de les déclarer conformes.

La protection contre les erreurs dépend aussi de la clé : pour le rollback, elle doit pouvoir lire et restaurer les sauvegardes (`core/backup`).

## Outils

| Domaine | Lecture | Écriture | Contenu |
|---|---:|---:|---|
| `system` | 13 | 2 | état, firmware, plugins, services, journaux, sauvegardes, configuration |
| `network` | 12 | 4 | interfaces, ARP/NDP, routage, passerelles, VLAN, routes statiques |
| `firewall` | 18 | 19 | règles, alias, catégories, journal, états pf, simulation, analyse, cycle de modification |
| `nat` | 7 | 8 | redirections de ports, NAT sortant, 1:1, NPTv6 |
| `dns` | 14 | 17 | Unbound : overrides, forwards, DNS sur TLS, listes de blocage, statistiques |
| `dhcp` | 10 | 11 | baux (Kea, Dnsmasq, ISC), plages, réservations |
| `vpn` | 8 | 1 | WireGuard, IPsec, OpenVPN |
| `services` | 11 | 6 | DynDNS, certificats, ACME, cron, CrowdSec, IDS, mDNS |
| `haproxy` | 14 | 23 | frontends, backends, serveurs, ACL, règles, health checks (à activer) |
| `diagnostics` | 6 | | ping, traceroute, DNS, test de port, enquête sur un hôte |
| `security` | 1 | | audit de sécurité |
| `api` | 3 | 1 | catalogue de 2471 points d'API, description des modèles, appels génériques |

Soit 103 outils en lecture seule par défaut, et 209 au maximum. Si votre client les charge tous dans son contexte, limitez avec `OPNSENSE_TOOLSETS=firewall,nat,diagnostics`. Pour afficher la liste exacte : `node dist/index.js --list-tools`.

Les noms reprennent ceux de [lucamarien/opnsense-mcp-server](https://github.com/lucamarien/opnsense-mcp-server) lorsque la fonction est la même, avec une différence pour HAProxy : un jeu d'outils par type d'objet, plutôt qu'un paramètre de type.

Le serveur fournit aussi des ressources (`opnsense://<instance>/status`, `interfaces`, `aliases`, `rules`) et quatre prompts : `firewall_security_review`, `troubleshoot_connectivity`, `safe_firewall_change`, `investigate_host`.

## Modifications du pare-feu

Les changements de règles et de NAT suivent toujours ce cycle :

```
opn_add_firewall_rule …           préparé : rien ne change encore sur le réseau
opn_simulate_firewall_traffic     (facultatif) le trafic passerait-il, et quelle règle décide ?
opn_apply_firewall_changes        contrôle du risque de blocage, puis mise en service
                                  → vérifier que tout fonctionne
opn_confirm_changes               rend le changement définitif
                                  sans confirmation, il est annulé à la fin du délai
```

### Ce que protège le rollback, et ce qu'il ne protège pas

**Avant OPNsense 26.7**, le serveur utilise le minuteur natif de 60 secondes. Il tourne sur le pare-feu : il se déclenche même si la connexion est perdue. Il ne couvre que les règles de filtrage et le NAT sortant.

**OPNsense 26.7 a supprimé ce minuteur** ([opnsense/core#10411](https://github.com/opnsense/core/issues/10411)). Le serveur note donc la dernière sauvegarde de configuration avant la première écriture, et la restaure si le changement n'est pas confirmé à temps.

**Limite importante : sur 26.7 et plus, ce minuteur tourne sur la machine qui héberge ce serveur, pas sur le pare-feu.** Si une règle coupe la connexion et qu'elle reste coupée, le serveur réessaie pendant 3 minutes, puis abandonne, et le changement reste actif. Il ne peut rien non plus si ce serveur s'arrête brutalement (coupure de courant, `kill -9`). Un arrêt normal, lui, annule les changements non confirmés.

C'est pourquoi le contrôle du risque de blocage s'exécute avant : il refuse d'appliquer si le chemin vers l'API serait coupé, ou s'il n'a pas pu le vérifier (tunnel SSH, proxy, VPN sans interface assignée). Il tient compte des alias préparés, des redirections de ports et des règles qui forcent une passerelle. Il reste une estimation à partir de la configuration, et il ne connaît pas votre routage ni ce qui se trouve devant le pare-feu. **Gardez un accès console pour tout changement risqué.**

Après l'application, le serveur teste l'accès sur une **nouvelle** connexion, car une connexion déjà ouverte survit au rechargement de pf et ne prouve rien.

Autres points à connaître :

- Une restauration remplace **toute** la configuration. Si la configuration a aussi été enregistrée en dehors du changement entre-temps, par quelqu'un d'autre ou par une écriture sur un service (DNS, DHCP…), le rollback s'arrête au lieu de l'effacer. Le changement reste alors actif et l'erreur est signalée. Le serveur reconnaît ses propres révisions : le nom de l'utilisateur ne suffit pas, car une personne peut utiliser le même compte.
- Une fois un changement appliqué, toute nouvelle écriture sur le pare-feu est refusée jusqu'à sa confirmation ou son annulation.
- Si le pare-feu ne confirme pas le rechargement, la réponse vaut `apply_outcome_unknown` : le changement est peut-être actif, et le minuteur tourne.
- Un changement préparé est enregistré dans la configuration. Tout rechargement du pare-feu, même lancé depuis l'interface web, le met en service.
- Les autres services (DNS, DHCP, routes, VPN…) n'ont **aucun minuteur** : ils changent dès le `reconfigure`. Leur réponse indique la sauvegarde à restaurer (`revert_with`).
- `opn_add_alias_entry`, `opn_remove_alias_entry`, `opn_kill_states` et `opn_api_write` agissent immédiatement.

## Sécurité

**Bloqué pour tous les outils**, sauf si l'opérateur le débloque avec `OPNSENSE_UNBLOCK` : arrêt et redémarrage, mises à jour, retour aux réglages d'usine, gestion des utilisateurs, des privilèges et des clés API, création et modification des tâches cron (elles peuvent lancer un redémarrage), vidage complet des états pf, suppression des sauvegardes, effacement des journaux, capture de paquets. Le blocage compare une forme canonique du chemin, car le routeur d'OPNsense accepte aussi `core/system/re_boot` et `REBOOT`.

**Cette liste n'est pas un bac à sable.** Avec les écritures activées, `opn_api_write` atteint tout ce qui n'y figure pas, et d'autres fonctions d'OPNsense peuvent exécuter des commandes (les tests personnalisés de Monit, par exemple). Une clé d'administrateur reste équivalente à un accès root : la vraie limite, ce sont les privilèges de la clé. Pour retirer les appels génériques, chargez seulement les domaines voulus avec `OPNSENSE_TOOLSETS`, sans `api`.

**Le verbe HTTP ne prouve rien sur OPNsense.** Certains GET modifient l'état (`acmeclient/service/reset`), et beaucoup de POST ne font que lire. L'accès se décide donc d'après le nom de la commande, et une commande inconnue compte comme une écriture.

**Secrets.** Mots de passe, clés et jetons sont masqués dans les réponses et dans le journal d'audit. Un corps de requête contenant `[REDACTED]` est refusé, pour éviter de réécrire ce masque à la place d'un vrai secret. Le masquage repose sur le nom des champs : un secret placé dans un champ de texte libre, comme une description, ne sera pas détecté, sauf les clés privées PEM.

**Injection de prompt.** Les journaux, les noms d'hôtes et les descriptions peuvent venir d'un attaquant. Le serveur le signale à l'agent, mais aucune instruction ne garantit qu'un modèle n'y réagira jamais. Sur un pare-feu exposé, gardez la lecture seule ou validez chaque écriture.

**Accès réseau.** En mode HTTP (`--http`), le serveur écoute sur `127.0.0.1` par défaut et refuse une autre adresse sans `OPNSENSE_MCP_TOKEN`. Il vérifie l'en-tête `Host`. Le chiffrement n'est pas fourni : placez un proxy TLS devant si le trafic quitte la machine. Ce mode n'a pas de session, donc pas de demande de confirmation humaine.

## Limites connues

- Le simulateur n'évalue qu'un sens sur une interface donnée, et ne connaît ni le shaping ni le routage par politique. Tout ce qu'il ne peut pas déterminer est signalé comme incertain. Une seule exception : un alias mêlant noms d'hôtes et adresses est résolu par sa table en service, qui ne reflète pas un retrait préparé.
- Avant 26.7, le pare-feu ne dit pas si l'annulation de son minuteur a réussi : `opn_confirm_changes` le signale, et il faut vérifier une fois le délai écoulé.
- Les compteurs pf repartent de zéro à chaque rechargement : un compteur à zéro ne prouve pas qu'une règle est inutile.
- L'absence d'une ligne de journal ne prouve pas l'absence de trafic : seules les règles avec journalisation en écrivent.
- Le catalogue vient de la documentation OPNsense. Il sert à la découverte, jamais au contrôle d'accès.
- L'audit de sécurité fait des contrôles automatiques. Aucun résultat ne vaut certification, et il ne contient volontairement aucune correspondance avec PCI-DSS ou le BSI, faute de pouvoir les vérifier.

## Développement

```bash
npm test            # tests, contre le faux serveur de test/fake-opnsense.ts
npm run typecheck
npm run build
npm run catalog     # régénère src/catalog/endpoints.json depuis la documentation
```

Pour tester sur un vrai pare-feu sans risque : clé API avec des privilèges en lecture, sans `OPNSENSE_ALLOW_WRITES`. Pour vérifier une écriture : `OPNSENSE_DRY_RUN=true` montre ce qui serait envoyé, sans rien envoyer.

## Version Rust (`rust/`)

Portage Rust complet de ce serveur : mêmes 209 outils, mêmes noms, descriptions, schémas et annotations (vérifié par `bench/parite.mjs`), même politique d'accès fail-closed, mêmes protections de rollback. Un seul binaire sans runtime Node.

```bash
cd rust && cargo build --release      # binaire : target/release/osmcp
```

Les variables d'environnement et les options (`--http`, `--host`, `--port`, `--list-tools`) sont identiques à la version TypeScript. Les binaires sont produits par le workflow `ci-rust.yml` (Linux x86_64 et arm64, macOS arm64, Windows), publiés en release sur un tag `v*`.

### TypeScript contre Rust

![Banc TypeScript contre Rust](bench/chart.svg)

Les mêmes requêtes MCP stdio sont envoyées aux deux serveurs, face à un faux pare-feu à latence nulle : on mesure le serveur MCP, pas le réseau. Le workflow `perf-bench.yml` teste les deux codes, relance le banc chaque lundi et à chaque changement, puis met à jour `bench/results.json`, `bench/results.md` et le graphe. En local : `node bench/bench.mjs && node bench/chart.mjs`.

## Remerciements

Ce projet reprend des idées de serveurs MCP existants :

- [lucamarien/opnsense-mcp-server](https://github.com/lucamarien/opnsense-mcp-server) : séparation par domaine, noms `opn_*`, lecture seule par défaut, redaction, audit.
- [vespo92/OPNSenseMCP](https://github.com/vespo92/OPNSenseMCP) : sécurité au point le plus bas, dry-run.
- [pacyworld/opnsense-mcp](https://github.com/pacyworld/opnsense-mcp) : plusieurs pare-feu.
- [Pixelworlds/opnsense-mcp-server](https://github.com/Pixelworlds/opnsense-mcp-server) : couverture de l'API, plugins sur demande.
- [aesaganda/opnsense-mcp](https://github.com/aesaganda/opnsense-mcp) : refus sans aucune requête, erreurs qui guident l'agent, honnêteté sur ce qu'un journal ne prouve pas.

## Licence

MIT
