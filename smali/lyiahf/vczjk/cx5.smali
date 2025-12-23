.class public final synthetic Llyiahf/vczjk/cx5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:J

.field public final synthetic OooOOO0:Llyiahf/vczjk/kl5;

.field public final synthetic OooOOOO:J

.field public final synthetic OooOOOo:F

.field public final synthetic OooOOo:Llyiahf/vczjk/a91;

.field public final synthetic OooOOo0:Llyiahf/vczjk/zy4;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/kl5;JJFLlyiahf/vczjk/zy4;Llyiahf/vczjk/a91;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/cx5;->OooOOO0:Llyiahf/vczjk/kl5;

    iput-wide p2, p0, Llyiahf/vczjk/cx5;->OooOOO:J

    iput-wide p4, p0, Llyiahf/vczjk/cx5;->OooOOOO:J

    iput p6, p0, Llyiahf/vczjk/cx5;->OooOOOo:F

    iput-object p7, p0, Llyiahf/vczjk/cx5;->OooOOo0:Llyiahf/vczjk/zy4;

    iput-object p8, p0, Llyiahf/vczjk/cx5;->OooOOo:Llyiahf/vczjk/a91;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const p1, 0x30007

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v9

    iget-object v7, p0, Llyiahf/vczjk/cx5;->OooOOo:Llyiahf/vczjk/a91;

    iget-object v0, p0, Llyiahf/vczjk/cx5;->OooOOO0:Llyiahf/vczjk/kl5;

    iget-wide v1, p0, Llyiahf/vczjk/cx5;->OooOOO:J

    iget-wide v3, p0, Llyiahf/vczjk/cx5;->OooOOOO:J

    iget v5, p0, Llyiahf/vczjk/cx5;->OooOOOo:F

    iget-object v6, p0, Llyiahf/vczjk/cx5;->OooOOo0:Llyiahf/vczjk/zy4;

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/hx5;->OooO00o(Llyiahf/vczjk/kl5;JJFLlyiahf/vczjk/zy4;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
