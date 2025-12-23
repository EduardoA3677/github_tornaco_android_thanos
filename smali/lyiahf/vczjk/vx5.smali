.class public final synthetic Llyiahf/vczjk/vx5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/hl5;

.field public final synthetic OooOOO0:Llyiahf/vczjk/zy4;

.field public final synthetic OooOOOO:Llyiahf/vczjk/pp3;

.field public final synthetic OooOOOo:J

.field public final synthetic OooOOo:F

.field public final synthetic OooOOo0:J

.field public final synthetic OooOOoo:Llyiahf/vczjk/z23;

.field public final synthetic OooOo0:I

.field public final synthetic OooOo00:Llyiahf/vczjk/a91;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/zy4;Llyiahf/vczjk/hl5;Llyiahf/vczjk/pp3;JJFLlyiahf/vczjk/z23;Llyiahf/vczjk/a91;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/vx5;->OooOOO0:Llyiahf/vczjk/zy4;

    iput-object p2, p0, Llyiahf/vczjk/vx5;->OooOOO:Llyiahf/vczjk/hl5;

    iput-object p3, p0, Llyiahf/vczjk/vx5;->OooOOOO:Llyiahf/vczjk/pp3;

    iput-wide p4, p0, Llyiahf/vczjk/vx5;->OooOOOo:J

    iput-wide p6, p0, Llyiahf/vczjk/vx5;->OooOOo0:J

    iput p8, p0, Llyiahf/vczjk/vx5;->OooOOo:F

    iput-object p9, p0, Llyiahf/vczjk/vx5;->OooOOoo:Llyiahf/vczjk/z23;

    iput-object p10, p0, Llyiahf/vczjk/vx5;->OooOo00:Llyiahf/vczjk/a91;

    iput p11, p0, Llyiahf/vczjk/vx5;->OooOo0:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    move-object v10, p1

    check-cast v10, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget p1, p0, Llyiahf/vczjk/vx5;->OooOo0:I

    or-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v11

    iget-object v9, p0, Llyiahf/vczjk/vx5;->OooOo00:Llyiahf/vczjk/a91;

    iget-object v0, p0, Llyiahf/vczjk/vx5;->OooOOO0:Llyiahf/vczjk/zy4;

    iget-object v1, p0, Llyiahf/vczjk/vx5;->OooOOO:Llyiahf/vczjk/hl5;

    iget-object v2, p0, Llyiahf/vczjk/vx5;->OooOOOO:Llyiahf/vczjk/pp3;

    iget-wide v3, p0, Llyiahf/vczjk/vx5;->OooOOOo:J

    iget-wide v5, p0, Llyiahf/vczjk/vx5;->OooOOo0:J

    iget v7, p0, Llyiahf/vczjk/vx5;->OooOOo:F

    iget-object v8, p0, Llyiahf/vczjk/vx5;->OooOOoo:Llyiahf/vczjk/z23;

    invoke-static/range {v0 .. v11}, Llyiahf/vczjk/yx5;->OooO0OO(Llyiahf/vczjk/zy4;Llyiahf/vczjk/hl5;Llyiahf/vczjk/pp3;JJFLlyiahf/vczjk/z23;Llyiahf/vczjk/a91;Llyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
