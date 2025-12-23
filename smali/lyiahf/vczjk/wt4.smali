.class public final Llyiahf/vczjk/wt4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/p29;


# instance fields
.field public final OooOOO:I

.field public final OooOOO0:I

.field public final OooOOOO:Llyiahf/vczjk/qs5;

.field public OooOOOo:I


# direct methods
.method static constructor <clinit>()V
    .locals 0

    return-void
.end method

.method public constructor <init>(III)V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p2, p0, Llyiahf/vczjk/wt4;->OooOOO0:I

    iput p3, p0, Llyiahf/vczjk/wt4;->OooOOO:I

    div-int v0, p1, p2

    mul-int/2addr v0, p2

    sub-int v1, v0, p3

    const/4 v2, 0x0

    invoke-static {v1, v2}, Ljava/lang/Math;->max(II)I

    move-result v1

    add-int/2addr v0, p2

    add-int/2addr v0, p3

    invoke-static {v1, v0}, Llyiahf/vczjk/vt6;->Oooo0oO(II)Llyiahf/vczjk/x14;

    move-result-object p2

    sget-object p3, Llyiahf/vczjk/rp3;->OooOo0O:Llyiahf/vczjk/rp3;

    invoke-static {p2, p3}, Landroidx/compose/runtime/OooO0o;->OooO(Ljava/lang/Object;Llyiahf/vczjk/gw8;)Llyiahf/vczjk/qs5;

    move-result-object p2

    iput-object p2, p0, Llyiahf/vczjk/wt4;->OooOOOO:Llyiahf/vczjk/qs5;

    iput p1, p0, Llyiahf/vczjk/wt4;->OooOOOo:I

    return-void
.end method


# virtual methods
.method public final OooO00o(I)V
    .locals 4

    iget v0, p0, Llyiahf/vczjk/wt4;->OooOOOo:I

    if-eq p1, v0, :cond_0

    iput p1, p0, Llyiahf/vczjk/wt4;->OooOOOo:I

    iget v0, p0, Llyiahf/vczjk/wt4;->OooOOO0:I

    div-int/2addr p1, v0

    mul-int/2addr p1, v0

    iget v1, p0, Llyiahf/vczjk/wt4;->OooOOO:I

    sub-int v2, p1, v1

    const/4 v3, 0x0

    invoke-static {v2, v3}, Ljava/lang/Math;->max(II)I

    move-result v2

    add-int/2addr p1, v0

    add-int/2addr p1, v1

    invoke-static {v2, p1}, Llyiahf/vczjk/vt6;->Oooo0oO(II)Llyiahf/vczjk/x14;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/wt4;->OooOOOO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :cond_0
    return-void
.end method

.method public final getValue()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wt4;->OooOOOO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/x14;

    return-object v0
.end method
