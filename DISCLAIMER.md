# DISCLAIMER / ДИСКЛЕЙМЕР

## English

This program is **educational** and is provided **as is**, for research and
learning purposes only.

- It is intended **only for testing the resilience of your own
  infrastructure** (your lab, your hosts, your network). Do not point it at
  systems you do not own or control, and do not run it on production hosts
  without a backup and a way to reboot.
- The tool sends **raw IP packets with IP options** to the target. Depending
  on the target kernel version and workload, this may cause **kernel
  panics, crashes, lost connections or dropped packets**. Kernel memory
  corruption (use-after-free) is, by design, a hard-to-predict event.
- **There is no guarantee** that the tool triggers the vulnerability on a
  given system, nor that a trigger is visible from the attacker side.
- The authors are **not liable** for data loss, downtime, hardware damage or
  any other consequence of using this program.

Use it at your own risk.

---

## Русский

Эта программа — **учебная** и предоставляется **«как есть»**, только для
исследовательских и образовательных целей.

- Она предназначена **исключительно для проверки устойчивости вашей
  собственной инфраструктуры** (ваша лаборатория, ваши хосты, ваша сеть).
  Не направляйте её на системы, которыми вы не владеете, и не запускайте на
  продуктивных хостах без резервной копии и возможности перезагрузки.
- Инструмент отправляет **сырые IP-пакеты с IP-опциями**. В зависимости от
  версии ядра и нагрузки на цели возможны **паники ядра, перезагрузки,
  потеря соединений и выпадение пакетов**. Повреждение памяти ядра
  (use-after-free) по своей природе непредсказуемо.
- **Никаких гарантий**, что уязвимость будет сработана на конкретной
  системе, и что срабатывание будет видно со стороны атакующего.
- Авторы **не несут ответственности** за потерю данных, простой,
  повреждение оборудования или иные последствия использования программы.

Используйте на свой страх и риск.
