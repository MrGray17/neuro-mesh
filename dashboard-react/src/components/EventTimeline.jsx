import React, { useEffect, useRef } from 'react';

const EventTimeline = ({ events }) => {
  const timelineRef = useRef(null);
  useEffect(() => {
    if (timelineRef.current) timelineRef.current.scrollTop = timelineRef.current.scrollHeight;
  }, [events]);
  return (
    <div className="panel p-events">
      <div className="panel-header">📅 EVENT TIMELINE</div>
      <div className="event-timeline" ref={timelineRef}>
        {events.length === 0 && <div className="event-entry">🟢 Système initialisé</div>}
        {events.map(event => (
          <div key={event.id} className={`event-entry ${event.type === 'attack' ? 'event-attack' : ''}`}>
            [{event.time}] {event.message}
          </div>
        ))}
      </div>
    </div>
  );
};
export default EventTimeline;
