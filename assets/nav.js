/* OXware shared nav behaviour — burger toggle + exclusive dropdown open. */
(function () {
  var burger = document.getElementById('nav-burger');
  var drawer = document.getElementById('mobile-drawer');
  if (burger && drawer) {
    burger.addEventListener('click', function () {
      drawer.classList.toggle('open');
      var icon = burger.querySelector('i');
      if (icon) {
        icon.className = drawer.classList.contains('open') ? 'fas fa-xmark' : 'fas fa-bars';
      }
    });
  }

  var dropdowns = document.querySelectorAll('.nav-primary > li.has-dropdown');
  function closeAll() {
    dropdowns.forEach(function (d) { d.classList.remove('dd-open'); });
  }
  dropdowns.forEach(function (li) {
    var trigger = li.querySelector('.nav-trigger');
    li.addEventListener('mouseenter', function () {
      closeAll();
      li.classList.add('dd-open');
    });
    li.addEventListener('mouseleave', function () {
      li.classList.remove('dd-open');
    });
    if (trigger) {
      trigger.addEventListener('click', function (e) {
        e.preventDefault();
        var isOpen = li.classList.contains('dd-open');
        closeAll();
        if (!isOpen) li.classList.add('dd-open');
      });
    }
  });
  document.addEventListener('click', function (e) {
    if (!e.target.closest('.nav-primary > li.has-dropdown')) closeAll();
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') closeAll();
  });
})();
