.class public final synthetic Llyiahf/vczjk/gw0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/rn9;

.field public final synthetic OooOOO0:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOO:J

.field public final synthetic OooOOOo:J

.field public final synthetic OooOOo:F

.field public final synthetic OooOOo0:J

.field public final synthetic OooOOoo:Llyiahf/vczjk/di6;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/a91;Llyiahf/vczjk/rn9;JJJFLlyiahf/vczjk/di6;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/gw0;->OooOOO0:Llyiahf/vczjk/a91;

    iput-object p2, p0, Llyiahf/vczjk/gw0;->OooOOO:Llyiahf/vczjk/rn9;

    iput-wide p3, p0, Llyiahf/vczjk/gw0;->OooOOOO:J

    iput-wide p5, p0, Llyiahf/vczjk/gw0;->OooOOOo:J

    iput-wide p7, p0, Llyiahf/vczjk/gw0;->OooOOo0:J

    iput p9, p0, Llyiahf/vczjk/gw0;->OooOOo:F

    iput-object p10, p0, Llyiahf/vczjk/gw0;->OooOOoo:Llyiahf/vczjk/di6;

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    move-object v10, p1

    check-cast v10, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/16 p1, 0x6001

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v11

    iget-object v0, p0, Llyiahf/vczjk/gw0;->OooOOO0:Llyiahf/vczjk/a91;

    iget v8, p0, Llyiahf/vczjk/gw0;->OooOOo:F

    iget-object v9, p0, Llyiahf/vczjk/gw0;->OooOOoo:Llyiahf/vczjk/di6;

    iget-object v1, p0, Llyiahf/vczjk/gw0;->OooOOO:Llyiahf/vczjk/rn9;

    iget-wide v2, p0, Llyiahf/vczjk/gw0;->OooOOOO:J

    iget-wide v4, p0, Llyiahf/vczjk/gw0;->OooOOOo:J

    iget-wide v6, p0, Llyiahf/vczjk/gw0;->OooOOo0:J

    invoke-static/range {v0 .. v11}, Llyiahf/vczjk/jw0;->OooO0OO(Llyiahf/vczjk/a91;Llyiahf/vczjk/rn9;JJJFLlyiahf/vczjk/di6;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
