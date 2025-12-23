.class public final synthetic Llyiahf/vczjk/xq0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/tv7;

.field public final synthetic OooOOO0:Llyiahf/vczjk/hl5;

.field public final synthetic OooOOOO:J

.field public final synthetic OooOOOo:Llyiahf/vczjk/le3;

.field public final synthetic OooOOo0:Llyiahf/vczjk/a91;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/hl5;Llyiahf/vczjk/tv7;JLlyiahf/vczjk/le3;Llyiahf/vczjk/a91;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/xq0;->OooOOO0:Llyiahf/vczjk/hl5;

    iput-object p2, p0, Llyiahf/vczjk/xq0;->OooOOO:Llyiahf/vczjk/tv7;

    iput-wide p3, p0, Llyiahf/vczjk/xq0;->OooOOOO:J

    iput-object p5, p0, Llyiahf/vczjk/xq0;->OooOOOo:Llyiahf/vczjk/le3;

    iput-object p6, p0, Llyiahf/vczjk/xq0;->OooOOo0:Llyiahf/vczjk/a91;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    move-object v6, p1

    check-cast v6, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 p1, 0x6001

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v7

    iget-object v5, p0, Llyiahf/vczjk/xq0;->OooOOo0:Llyiahf/vczjk/a91;

    iget-object v0, p0, Llyiahf/vczjk/xq0;->OooOOO0:Llyiahf/vczjk/hl5;

    iget-object v1, p0, Llyiahf/vczjk/xq0;->OooOOO:Llyiahf/vczjk/tv7;

    iget-wide v2, p0, Llyiahf/vczjk/xq0;->OooOOOO:J

    iget-object v4, p0, Llyiahf/vczjk/xq0;->OooOOOo:Llyiahf/vczjk/le3;

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/nqa;->OooOO0o(Llyiahf/vczjk/hl5;Llyiahf/vczjk/tv7;JLlyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
