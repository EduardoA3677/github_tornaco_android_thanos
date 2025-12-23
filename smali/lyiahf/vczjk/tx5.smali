.class public final synthetic Llyiahf/vczjk/tx5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/pp3;

.field public final synthetic OooOOO0:Llyiahf/vczjk/hl5;

.field public final synthetic OooOOOO:J

.field public final synthetic OooOOOo:J

.field public final synthetic OooOOo:Llyiahf/vczjk/zy4;

.field public final synthetic OooOOo0:F

.field public final synthetic OooOOoo:Llyiahf/vczjk/a91;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/hl5;Llyiahf/vczjk/pp3;JJFLlyiahf/vczjk/zy4;Llyiahf/vczjk/a91;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/tx5;->OooOOO0:Llyiahf/vczjk/hl5;

    iput-object p2, p0, Llyiahf/vczjk/tx5;->OooOOO:Llyiahf/vczjk/pp3;

    iput-wide p3, p0, Llyiahf/vczjk/tx5;->OooOOOO:J

    iput-wide p5, p0, Llyiahf/vczjk/tx5;->OooOOOo:J

    iput p7, p0, Llyiahf/vczjk/tx5;->OooOOo0:F

    iput-object p8, p0, Llyiahf/vczjk/tx5;->OooOOo:Llyiahf/vczjk/zy4;

    iput-object p9, p0, Llyiahf/vczjk/tx5;->OooOOoo:Llyiahf/vczjk/a91;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    move-object v9, p1

    check-cast v9, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const p1, 0x186001

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v10

    iget-object v8, p0, Llyiahf/vczjk/tx5;->OooOOoo:Llyiahf/vczjk/a91;

    iget-object v0, p0, Llyiahf/vczjk/tx5;->OooOOO0:Llyiahf/vczjk/hl5;

    iget-object v1, p0, Llyiahf/vczjk/tx5;->OooOOO:Llyiahf/vczjk/pp3;

    iget-wide v2, p0, Llyiahf/vczjk/tx5;->OooOOOO:J

    iget-wide v4, p0, Llyiahf/vczjk/tx5;->OooOOOo:J

    iget v6, p0, Llyiahf/vczjk/tx5;->OooOOo0:F

    iget-object v7, p0, Llyiahf/vczjk/tx5;->OooOOo:Llyiahf/vczjk/zy4;

    invoke-static/range {v0 .. v10}, Llyiahf/vczjk/yx5;->OooO00o(Llyiahf/vczjk/hl5;Llyiahf/vczjk/pp3;JJFLlyiahf/vczjk/zy4;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
