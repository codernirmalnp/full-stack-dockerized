import Link from "next/link";
type BreadCrumbItem={
    children:React.ReactNode,
    href:string
}
const BreadcrumbItem:React.FC<BreadCrumbItem> = ({ children, href, ...props }) => {
    return (
        <li {...props}>
            <Link href={href} passHref legacyBehavior>
                <a>{children}</a>
            </Link>
        </li>
    );
};

export default BreadcrumbItem;