import styles from './platform-dashboard.module.scss'

export function PlatformPage({ title, subtitle, children, right }: { title:string; subtitle:string; children:React.ReactNode; right?:React.ReactNode }) {
  return <div className={styles.page}><div className={styles.toolbar}><div><h2 className={styles.heading}>{title}</h2><p className={styles.subheading}>{subtitle}</p></div>{right}</div>{children}</div>
}
export function Stats({ items }: { items:{label:string;value:React.ReactNode;meta?:string}[] }) {
  return <div className={styles.stats}>{items.map(item => <div className={styles.stat} key={item.label}><div className={styles.statLabel}>{item.label}</div><div className={styles.statValue}>{item.value}</div><div className={styles.statMeta}>{item.meta}</div></div>)}</div>
}
export function Card({ title, children }: { title:string; children:React.ReactNode }) { return <section className={styles.card}><h3>{title}</h3>{children}</section> }
export function Grid({ children }: { children:React.ReactNode }) { return <div className={styles.grid2}>{children}</div> }
export function Badge({ value }: { value:string }) { const tone=value.toLowerCase(); return <span className={`${styles.badge} ${styles[tone as 'high'|'medium'|'low'] ?? ''}`}>{value}</span> }
export { styles as platformStyles }
