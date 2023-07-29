import React from 'react'
type TableHead = {
    list: Array<[{ title: string}]>
}

export const TableHeader: React.FC<TableHead> = ({ list }) => {
    return (
        <thead>
            <tr>
                {list.map(( title,key) => {
                    return (
                        <th
                            className="px-5 py-3 border-b-2 border-gray-200 bg-gray-100 text-left text-xs font-semibold text-gray-600 uppercase tracking-wider"  key={key}>
                            {/* {title} */}Hello
                        </th>)
                })}


            </tr>
        </thead>
    )
}
