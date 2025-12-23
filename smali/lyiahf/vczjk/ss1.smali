.class public final Llyiahf/vczjk/ss1;
.super Llyiahf/vczjk/mc4;
.source "SourceFile"


# instance fields
.field public final OooOo:Llyiahf/vczjk/t4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/t4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ss1;->OooOo:Llyiahf/vczjk/t4;

    return-void
.end method


# virtual methods
.method public final OooOOOO(ILlyiahf/vczjk/yn4;Llyiahf/vczjk/ow6;I)I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ss1;->OooOo:Llyiahf/vczjk/t4;

    iget-object v0, v0, Llyiahf/vczjk/t4;->OooO00o:Llyiahf/vczjk/go3;

    invoke-virtual {p3, v0}, Llyiahf/vczjk/ow6;->OooooOO(Llyiahf/vczjk/p4;)I

    move-result p3

    const/high16 v0, -0x80000000

    if-eq p3, v0, :cond_1

    sub-int/2addr p4, p3

    sget-object p3, Llyiahf/vczjk/yn4;->OooOOO:Llyiahf/vczjk/yn4;

    if-ne p2, p3, :cond_0

    sub-int/2addr p1, p4

    return p1

    :cond_0
    return p4

    :cond_1
    const/4 p1, 0x0

    return p1
.end method

.method public final OooOOOo(Llyiahf/vczjk/ow6;)Ljava/lang/Integer;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ss1;->OooOo:Llyiahf/vczjk/t4;

    iget-object v0, v0, Llyiahf/vczjk/t4;->OooO00o:Llyiahf/vczjk/go3;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ow6;->OooooOO(Llyiahf/vczjk/p4;)I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    return-object p1
.end method
