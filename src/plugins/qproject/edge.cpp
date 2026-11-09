/****************************************************************************
**
** Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies).
** All rights reserved.
** Contact: Nokia Corporation (qt-info@nokia.com)
**
** This file is part of the examples of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial Usage
** Licensees holding valid Qt Commercial licenses may use this file in
** accordance with the Qt Commercial License Agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and Nokia.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 2.1 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL included in the
** packaging of this file.  Please review the following information to
** ensure the GNU Lesser General Public License version 2.1 requirements
** will be met: http://www.gnu.org/licenses/old-licenses/lgpl-2.1.html.
**
** In addition, as a special exception, Nokia gives you certain additional
** rights.  These rights are described in the Nokia Qt LGPL Exception
** version 1.1, included in the file LGPL_EXCEPTION.txt in this package.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 3.0 as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL included in the
** packaging of this file.  Please review the following information to
** ensure the GNU General Public License version 3.0 requirements will be
** met: http://www.gnu.org/copyleft/gpl.html.
**
** If you have questions regarding the use of this file, please contact
** Nokia at qt-info@nokia.com.
** $QT_END_LICENSE$
**
****************************************************************************/

//lint -e4206 'nodiscard' attribute cannot be applied to types
#ifdef __NT__
#pragma warning(push)
#pragma warning(disable:5219) // implicit conversion from 'int' to 'float', possible loss of data
#pragma warning(disable:5240) // 'nodiscard': attribute is ignored in this syntactic position
#endif // __NT__

#include <QPainter>

#include "edge.h"
#include "node.h"

#ifdef __NT__
#pragma warning(pop)
#endif // __NT__

#include <math.h>

//lint -e1535 member function '' exposes lower access pointer member ''
//lint -e1536 member function '' exposes lower access member ''
//lint -e1537 const member function '' exposes pointer member '' as pointer to non-const
//lint -e1540 non-static pointer data member '' not deallocated nor zeroed by destructor
//lint -e2466 '' was used despite being marked as 'unused'

static const double Pi = 3.14159265358979323846264338327950288419717;
static const double TwoPi = 2.0 * Pi;

Edge::Edge(Node *_sourceNode, Node *_destNode)
  : arrowSize(10)
{
  setAcceptedMouseButtons(Qt::MouseButtons());
  source = _sourceNode;
  dest = _destNode;
  source->addEdge(this);
  dest->addEdge(this);
  adjust();
}

Edge::~Edge()
{
}

Node *Edge::sourceNode() const
{
  return source;
}

void Edge::setSourceNode(Node *node)
{
  source = node;
  adjust();
}

Node *Edge::destNode() const
{
  return dest;
}

void Edge::setDestNode(Node *node)
{
  dest = node;
  adjust();
}

void Edge::adjust()
{
  if ( !source || !dest )
    return;

  QRectF srect = source->boundingRect();
  QRectF drect = dest->boundingRect();

  QLineF line(mapFromItem(source, srect.width() / 2, srect.height() / 2),
              mapFromItem(dest, drect.width() / 2, drect.height() / 2));
  qreal length = line.length();

  prepareGeometryChange();

  if ( length > qreal(40.) )
  {
    qreal line_angle = line.angle();
    qreal angle = line_angle > 90. ? fmod(line_angle, 90.0) : line_angle;
    qreal dist = qMax(angle, 45.0) - qMin(angle, 45.0);
    dist += 80.0 - dist;
    QPointF edgeOffset((line.dx() * dist) / length, (line.dy() * dist) / length);
    sourcePoint = line.p1() + edgeOffset;
    destPoint = line.p2() - edgeOffset;
    qreal new_angle = QLineF(sourcePoint, destPoint).angle();
    if ( qAbs(new_angle - line_angle) > 90. )
      sourcePoint = destPoint = line.p1();
  }
  else
  {
    sourcePoint = destPoint = line.p1();
  }
}

QRectF Edge::boundingRect() const
{
  if ( !source || !dest )
    return QRectF();

  qreal penWidth = 1;
  qreal extra = (penWidth + arrowSize) / 2.0;

  QRectF r(sourcePoint, QSizeF(destPoint.x() - sourcePoint.x(),
                               destPoint.y() - sourcePoint.y()));

  return r.normalized().adjusted(-extra, -extra, extra, extra);
}

void Edge::paint(QPainter *painter, const QStyleOptionGraphicsItem *, QWidget *)
{
  if ( !source || !dest )
    return;

  QLineF line(sourcePoint, destPoint);
  if ( qFuzzyCompare(line.length(), qreal(0.)) )
    return;

  // Draw the line itself
  painter->setPen(QPen(Qt::black, 1, Qt::SolidLine, Qt::RoundCap, Qt::RoundJoin));
  painter->drawLine(line);

  // Draw the arrows
  double angle = ::acos(line.dx() / line.length());
  if ( line.dy() >= 0 )
    angle = TwoPi - angle;

  QPointF destArrowP1 = destPoint + QPointF(sin(angle - Pi / 3) * arrowSize,
                                            cos(angle - Pi / 3) * arrowSize);
  QPointF destArrowP2 = destPoint + QPointF(sin(angle - Pi + Pi / 3) * arrowSize,
                                            cos(angle - Pi + Pi / 3) * arrowSize);

  painter->setBrush(Qt::black);

  painter->drawPolygon(QPolygonF() << line.p2() << destArrowP1 << destArrowP2);
}
