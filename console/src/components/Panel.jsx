function Panel({ title, children }) {
  return (
    <div className="panel">
      {title && <div className="panel-label">{title}</div>}

      <div className="panel-body">
        {children}
      </div>
    </div>
  );
}

export default Panel;