.class public final synthetic Llyiahf/vczjk/or9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/sr9;

.field public final synthetic OooOOO0:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOOO:F


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ow6;Llyiahf/vczjk/sr9;F)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/or9;->OooOOO0:Llyiahf/vczjk/ow6;

    iput-object p2, p0, Llyiahf/vczjk/or9;->OooOOO:Llyiahf/vczjk/sr9;

    iput p3, p0, Llyiahf/vczjk/or9;->OooOOOO:F

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/nw6;

    iget-object v0, p0, Llyiahf/vczjk/or9;->OooOOO:Llyiahf/vczjk/sr9;

    iget-object v0, v0, Llyiahf/vczjk/sr9;->OooOooo:Llyiahf/vczjk/gi;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    :goto_0
    float-to-int v0, v0

    goto :goto_1

    :cond_0
    iget v0, p0, Llyiahf/vczjk/or9;->OooOOOO:F

    goto :goto_0

    :goto_1
    iget-object v1, p0, Llyiahf/vczjk/or9;->OooOOO0:Llyiahf/vczjk/ow6;

    const/4 v2, 0x0

    invoke-static {p1, v1, v0, v2}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
