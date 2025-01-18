    let lastScrollTop = 0;
    const navbar = document.querySelector('.navbar');

    window.addEventListener('scroll', () => {
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        if (scrollTop > lastScrollTop) {
            navbar.style.top = '-70px'; // Hide on scroll down
        } else {
            navbar.style.top = '0'; // Show on scroll up
        }
        lastScrollTop = scrollTop;
    });