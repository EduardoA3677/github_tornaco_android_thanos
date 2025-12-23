.class public final Llyiahf/vczjk/gv1;
.super Llyiahf/vczjk/je5;
.source "SourceFile"


# instance fields
.field public final OooOOoo:Landroid/graphics/RectF;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gv1;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/je5;-><init>(Llyiahf/vczjk/je5;)V

    iget-object p1, p1, Llyiahf/vczjk/gv1;->OooOOoo:Landroid/graphics/RectF;

    iput-object p1, p0, Llyiahf/vczjk/gv1;->OooOOoo:Landroid/graphics/RectF;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/tj8;Landroid/graphics/RectF;)V
    .locals 0

    invoke-direct {p0, p1}, Llyiahf/vczjk/je5;-><init>(Llyiahf/vczjk/tj8;)V

    iput-object p2, p0, Llyiahf/vczjk/gv1;->OooOOoo:Landroid/graphics/RectF;

    return-void
.end method


# virtual methods
.method public final newDrawable()Landroid/graphics/drawable/Drawable;
    .locals 1

    new-instance v0, Llyiahf/vczjk/hv1;

    invoke-direct {v0, p0}, Llyiahf/vczjk/le5;-><init>(Llyiahf/vczjk/je5;)V

    iput-object p0, v0, Llyiahf/vczjk/hv1;->OoooO:Llyiahf/vczjk/gv1;

    invoke-virtual {v0}, Llyiahf/vczjk/le5;->invalidateSelf()V

    return-object v0
.end method
