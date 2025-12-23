.class public final synthetic Llyiahf/vczjk/eu8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOO0:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOo:Llyiahf/vczjk/rn9;

.field public final synthetic OooOOo:J

.field public final synthetic OooOOo0:J


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rn9;JJI)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/eu8;->OooOOO0:Llyiahf/vczjk/a91;

    iput-object p2, p0, Llyiahf/vczjk/eu8;->OooOOO:Llyiahf/vczjk/a91;

    iput-object p3, p0, Llyiahf/vczjk/eu8;->OooOOOO:Llyiahf/vczjk/a91;

    iput-object p4, p0, Llyiahf/vczjk/eu8;->OooOOOo:Llyiahf/vczjk/rn9;

    iput-wide p5, p0, Llyiahf/vczjk/eu8;->OooOOo0:J

    iput-wide p7, p0, Llyiahf/vczjk/eu8;->OooOOo:J

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v9

    iget-object v0, p0, Llyiahf/vczjk/eu8;->OooOOO0:Llyiahf/vczjk/a91;

    iget-wide v4, p0, Llyiahf/vczjk/eu8;->OooOOo0:J

    iget-wide v6, p0, Llyiahf/vczjk/eu8;->OooOOo:J

    iget-object v1, p0, Llyiahf/vczjk/eu8;->OooOOO:Llyiahf/vczjk/a91;

    iget-object v2, p0, Llyiahf/vczjk/eu8;->OooOOOO:Llyiahf/vczjk/a91;

    iget-object v3, p0, Llyiahf/vczjk/eu8;->OooOOOo:Llyiahf/vczjk/rn9;

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/lu8;->OooO00o(Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/rn9;JJLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
