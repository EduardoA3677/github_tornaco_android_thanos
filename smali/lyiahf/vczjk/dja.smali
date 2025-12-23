.class public abstract Llyiahf/vczjk/dja;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/jja;

.field public static final OooO0O0:Llyiahf/vczjk/cs0;

.field public static final OooO0OO:Llyiahf/vczjk/cs0;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1d

    if-lt v0, v1, :cond_0

    new-instance v0, Llyiahf/vczjk/kja;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/dja;->OooO00o:Llyiahf/vczjk/jja;

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/jja;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/dja;->OooO00o:Llyiahf/vczjk/jja;

    :goto_0
    new-instance v0, Llyiahf/vczjk/cs0;

    const-class v1, Ljava/lang/Float;

    const-string v2, "translationAlpha"

    const/16 v3, 0x15

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/cs0;-><init>(Ljava/lang/Class;Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/dja;->OooO0O0:Llyiahf/vczjk/cs0;

    new-instance v0, Llyiahf/vczjk/cs0;

    const-class v1, Landroid/graphics/Rect;

    const-string v2, "clipBounds"

    const/16 v3, 0x16

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/cs0;-><init>(Ljava/lang/Class;Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/dja;->OooO0OO:Llyiahf/vczjk/cs0;

    return-void
.end method

.method public static OooO00o(Landroid/view/View;IIII)V
    .locals 6

    sget-object v0, Llyiahf/vczjk/dja;->OooO00o:Llyiahf/vczjk/jja;

    move-object v1, p0

    move v2, p1

    move v3, p2

    move v4, p3

    move v5, p4

    invoke-virtual/range {v0 .. v5}, Llyiahf/vczjk/jja;->Oooo000(Landroid/view/View;IIII)V

    return-void
.end method

.method public static OooO0O0(Landroid/view/View;F)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/dja;->OooO00o:Llyiahf/vczjk/jja;

    invoke-virtual {v0, p0, p1}, Llyiahf/vczjk/ht6;->OooOo(Landroid/view/View;F)V

    return-void
.end method

.method public static OooO0OO(Landroid/view/View;I)V
    .locals 1

    sget-object v0, Llyiahf/vczjk/dja;->OooO00o:Llyiahf/vczjk/jja;

    invoke-virtual {v0, p0, p1}, Llyiahf/vczjk/jja;->OooOoO0(Landroid/view/View;I)V

    return-void
.end method
