.class public final Llyiahf/vczjk/eh2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $maxValue:F

.field final synthetic $minValue:F


# direct methods
.method public constructor <init>(FF)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/eh2;->$minValue:F

    iput p2, p0, Llyiahf/vczjk/eh2;->$maxValue:F

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/pf2;

    sget-object v0, Llyiahf/vczjk/ni2;->OooOOO0:Llyiahf/vczjk/ni2;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x0

    throw p1
.end method
