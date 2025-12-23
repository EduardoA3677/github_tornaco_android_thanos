.class public final synthetic Llyiahf/vczjk/lo3;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:F

.field public final synthetic OooOOO0:F

.field public final synthetic OooOOOO:F

.field public final synthetic OooOOOo:Llyiahf/vczjk/ow6;


# direct methods
.method public synthetic constructor <init>(FFFLlyiahf/vczjk/ow6;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Llyiahf/vczjk/lo3;->OooOOO0:F

    iput p2, p0, Llyiahf/vczjk/lo3;->OooOOO:F

    iput p3, p0, Llyiahf/vczjk/lo3;->OooOOOO:F

    iput-object p4, p0, Llyiahf/vczjk/lo3;->OooOOOo:Llyiahf/vczjk/ow6;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/nw6;

    iget v0, p0, Llyiahf/vczjk/lo3;->OooOOO:F

    iget v1, p0, Llyiahf/vczjk/lo3;->OooOOOO:F

    iget v2, p0, Llyiahf/vczjk/lo3;->OooOOO0:F

    invoke-static {v2, v0, v1}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result v0

    invoke-static {v0}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/lo3;->OooOOOo:Llyiahf/vczjk/ow6;

    const/4 v2, 0x0

    invoke-static {p1, v1, v0, v2}, Llyiahf/vczjk/nw6;->OooO0o(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
