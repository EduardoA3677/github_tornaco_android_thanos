.class public final synthetic Llyiahf/vczjk/fq;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOO0:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOO:I

.field public final synthetic OooOOOo:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOo0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/kl5;ILlyiahf/vczjk/oe3;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/fq;->OooOOO0:Llyiahf/vczjk/a91;

    iput-object p2, p0, Llyiahf/vczjk/fq;->OooOOO:Llyiahf/vczjk/kl5;

    iput p3, p0, Llyiahf/vczjk/fq;->OooOOOO:I

    iput-object p4, p0, Llyiahf/vczjk/fq;->OooOOOo:Llyiahf/vczjk/oe3;

    iput p5, p0, Llyiahf/vczjk/fq;->OooOOo0:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/fq;->OooOOo0:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object v0, p0, Llyiahf/vczjk/fq;->OooOOO0:Llyiahf/vczjk/a91;

    iget v2, p0, Llyiahf/vczjk/fq;->OooOOOO:I

    iget-object v3, p0, Llyiahf/vczjk/fq;->OooOOOo:Llyiahf/vczjk/oe3;

    iget-object v1, p0, Llyiahf/vczjk/fq;->OooOOO:Llyiahf/vczjk/kl5;

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/ye5;->OooO00o(Llyiahf/vczjk/a91;Llyiahf/vczjk/kl5;ILlyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
