let sonarTimeout = null;

export const playSonar = () => {
  const radar = document.querySelector('.radar');
  if (!radar) return;
  if (sonarTimeout) {
    radar.classList.remove('sonar-active');
    clearTimeout(sonarTimeout);
  }
  void radar.offsetWidth;
  radar.classList.add('sonar-active');
  sonarTimeout = setTimeout(() => {
    radar.classList.remove('sonar-active');
    sonarTimeout = null;
  }, 1000);
};
