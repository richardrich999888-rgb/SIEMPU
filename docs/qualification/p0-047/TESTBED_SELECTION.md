# D2/D8: research and smallest useful testbed

Sources checked 12 November 2026 IST. No application, allocation, institutional approval,
fee waiver, spectrum permission or acceptance of terms was obtained. Pricing, capacity,
quotas and rules must be reconfirmed by the selected operator before use.

**Selection:** use five allocated Linux VMs for the live A–E path, add an isolated sixth
VM for F before handover/partition work. Even three hosts can test one narrower property
(sender/recipient, authority/relay, separate custodian), but cannot meet the requested
six-node separation. Start with controlled private networking before authorised public
network trials. No cellular core or RF hardware is needed to test current-policy release.
CORE/Mininet provide repeatability, not independent kernels. Budget is zero only if
existing authorised hosts or a granted research allocation are available.

| Project                                                                                                                                                                    | Useful capability and prerequisites                                                           | Decision                                                                                                                                                         |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [CORE](https://github.com/coreemu/core), [Python API](https://coreemu.github.io/core/python.html)                                                                          | Executes real processes in namespaces; link delay, jitter, loss, duplication; root required   | Adapter supplied; execution BLOCKED here. Record installed revision and actual qdisc counters                                                                    |
| [Mininet](https://github.com/mininet/mininet), [API](https://mininet.org/api/classmininet_1_1net_1_1Mininet.html)                                                          | Namespaces and virtual links with actual service processes; privileged Linux                  | First emulator choice for small reproducible wired topology; not physical-network evidence                                                                       |
| [EMANE](https://github.com/adjacentlink/emane), [CORE integration](https://coreemu.github.io/core/emane.html)                                                              | Wireless link/MAC modelling adds controlled RF-channel effects                                | Defer until a sponsor specifies wireless conditions; no EMANE measurement claimed                                                                                |
| [Open5GS](https://github.com/open5gs/open5gs)                                                                                                                              | Real open-source LTE/5G core; needs configured UE/RAN and routing                             | Optional approved cellular lab transport, not required for cryptographic-policy hypotheses                                                                       |
| [srsRAN Project](https://github.com/srsran/srsRAN_Project), [ZeroMQ tutorial](https://docs.srsran.com/projects/project/en/latest/tutorials/source/srsUE/source/index.html) | gNB and compatible srsUE/ZeroMQ permit software radio links; physical RF needs lab permission | Requested repository is archived (observed primary GitHub page); choose/pin a maintained lab-approved stack before adoption. ZeroMQ is not over-the-air evidence |

## Research allocations

| Facility                                     | Eligibility / application                                                                                                                       | Resources / quotas / costs                                                                                                                                                   | Permitted scope and SYNTRIASS status                                                                                                                                                                                                                                   |
| -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [FABRIC](https://portal.fabric-testbed.net/) | Enrol, obtain approved project membership and project-lead review. India-based lead needs exception/international review or an eligible partner | Default project limits include 2 cores, 10 GiB RAM/disk per VM and single site. Multisite/greater resources require tags; not a promised allocation                          | Research/education, no production or personal commercial gain. Seek written scope approval for isolated fault tests. BLOCKED: account/project/exception and host allocation                                                                                            |
| [CloudLab](https://cloudlab.us/)             | New project reviewed for research value; senior faculty/research staff or comparable lead; SSH key and individual accounts                      | Bare-metal examples: m510 8 cores/64 GiB/256 GB NVMe; xl170 10 cores/64 GiB/480 GB SSD. Availability and reservations are dynamic, no quota reserved                         | AUP prohibits commercial activity and attacks on infrastructure, including red-team experiments. Use only approved reproducible cloud-systems research, not a commercial qualification campaign disguised as research. BLOCKED: eligible project and written scope fit |
| [POWDER](https://powderwireless.net/)        | Project approval, senior lead, separate user accounts/SSH keys; contact support                                                                 | Compute/SDR/conducted/OTA resources. NSF academic use is free; other users' short platform evaluation may be free, later use may cost. No guaranteed free product validation | `powder-support@powderwireless.net` for account/experiment; `powder-contact@powderwireless.net` for commercial terms. Spectrum and failure-injection permissions require confirmation. BLOCKED: allocation, rules and costs                                            |

Primary policies: [FABRIC roles/limits](https://learn.fabric-testbed.net/knowledge-base/fabric-user-roles-and-project-permissions/),
[lead policy](https://learn.fabric-testbed.net/knowledge-base/fabric-project-lead-policy/),
[AUP](https://learn.fabric-testbed.net/knowledge-base/fabric-acceptable-use-policy-aup/);
[CloudLab users](https://docs.cloudlab.us/users.html), [hardware](https://docs.cloudlab.us/hardware.html),
[AUP](https://www.cloudlab.us/aup.php);
[POWDER users](https://docs.powderwireless.net/users.html), [hardware](https://docs.powderwireless.net/hardware.html),
[overview/cost](https://docs.powderwireless.net/powder-overview.html).
No numerical CloudLab/POWDER allocation quota was confirmed for this applicant. No
public permission for this exact security campaign was found. Request explicit review.

## India access routes

| Route                                                 | Verified route/contact                                                                                                                                                                                                                 | Applicant fit and unresolved conditions                                                                                                                                                                                                                                                              |
| ----------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C-DOT India 5G Alliance / Collaborative Research Cell | [Alliance](https://www.cdot.in/cdotweb/web/5ghome.php?lang=en), [official interest form](https://www.cdot.in/cdotweb/web/join5g.php)                                                                                                   | Includes application/security/enterprise consortiums and described campus testing. Suitable inquiry, not proven eligibility/access. Ask current facility, supervision, costs, partner terms and non-classified scope. Alliance page contains historical programme text; confirm current availability |
| DoT 5G Use Case Lab at IIT Tirupati                   | [Lab](https://ee.iittp.ac.in/5G_Lab.html); [department](https://ee.iittp.ac.in/Contact_us.html): `ee_office@iittp.ac.in`; [directory](https://www.iittp.ac.in/TD/index.php?dept=RUU%3D): `vijayaakarapu@iittp.ac.in`                   | Regional Andhra Pradesh option. Request routing to lab faculty/operator and external-startup access terms. No automatic startup entitlement, available VM configuration or fee waiver established                                                                                                    |
| TCoE TDIP pilot/validation programme                  | [Portal](https://pilot.tcoe.in/) public programme contact: `pilot@tcoe.in`, +91 9218464174; [general TCoE contact](https://tcoe.in/contactus): `info@tcoe.in`                                                                          | Published programme requires DPIIT startup or Udyam MSME, Indian ownership/control, working prototype, partner consent, and TRL 5–8. Provisional TRL 4 does not meet that maturity gate. Later route after justified relevant-environment evidence, not a reason to inflate TRL                      |
| IIT Hyderabad indigenous testbed                      | [Official usage/registration portal](https://5gtestbed.in/testbedusage.jsp): `5gtbadmin@5g.iith.ac.in`; [testbed-manager directory](https://user.cewit.org.in/5gtb/linkfiles/new/ContactDetail.html): `5gtestbedmanager@5g.iith.ac.in` | University lab alternative for end-to-end interoperability. Ask whether application-layer data-plane experiments and independent compute/custody are available; tariff/allocation and rules unconfirmed                                                                                              |

TCoE's official programme announcement states up to ₹50 lakh and up to 80% approved
cost support at its TRL 5–8 entry gate: [TCoE announcement](https://www.linkedin.com/posts/tcoe-india_dot-tcoeindia-tdip-activity-7487909847988887552-wRmu).
The official portal's public [programme-content endpoint](https://pilot.tcoe.in/api/cms/content),
read on 12 November 2026 IST, confirms those conditions, a minimum 20% beneficiary
contribution, and the pilot contact above.
This is not a ₹0 offer, awarded funding or confirmed SYNTRIASS eligibility. Statutory
recognition, ownership, partner consent, finances and the live guideline must be checked
by the founder before application. The separate DCIS programme must not be confused
with this pilot call.

The [2023 free-testbed notice](https://www.pib.gov.in/PressReleasePage.aspx?PRID=1902765)
expired in January 2024; it cannot establish free access now. The
[DoT lab directory](https://www.dot.gov.in/static/uploads/2026/05/f7816fc9d380529182b62925ef38b96b.pdf)
lists five Andhra Pradesh labs including IIT Tirupati and IIITDM Kurnool.
Use a host laboratory's authorised radio setup; do not transmit independently. Confirm
current licence procedures with the lab/WPC: the [DoT service page](https://eservices.dot.gov.in/experimental-license-100-5g-labs)
also carries migration notices for the 2026 authorisation portal. No licence is applied
for or legal eligibility determined by this research package.
