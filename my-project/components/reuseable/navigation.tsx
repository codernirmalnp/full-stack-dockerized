import Link from 'next/link'
import React from 'react'
type Nav = {
    children: React.ReactElement,
    href: string
}

export const Navigation: React.FC<Nav> = ({ children, href }) => {
    return (
        <Link href={`${href}`}>{children}</Link>
    )
}
