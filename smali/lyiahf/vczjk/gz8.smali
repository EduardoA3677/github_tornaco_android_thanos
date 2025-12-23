.class public final synthetic Llyiahf/vczjk/gz8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOO0:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOO:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOo:F

.field public final synthetic OooOOo0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/kl5;FI)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/gz8;->OooOOO0:Llyiahf/vczjk/a91;

    iput-object p2, p0, Llyiahf/vczjk/gz8;->OooOOO:Llyiahf/vczjk/a91;

    iput-object p3, p0, Llyiahf/vczjk/gz8;->OooOOOO:Llyiahf/vczjk/kl5;

    iput p4, p0, Llyiahf/vczjk/gz8;->OooOOOo:F

    iput p5, p0, Llyiahf/vczjk/gz8;->OooOOo0:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/gz8;->OooOOo0:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v5

    iget-object v0, p0, Llyiahf/vczjk/gz8;->OooOOO0:Llyiahf/vczjk/a91;

    iget-object v1, p0, Llyiahf/vczjk/gz8;->OooOOO:Llyiahf/vczjk/a91;

    iget-object v2, p0, Llyiahf/vczjk/gz8;->OooOOOO:Llyiahf/vczjk/kl5;

    iget v3, p0, Llyiahf/vczjk/gz8;->OooOOOo:F

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/vl6;->OooO00o(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/kl5;FLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
