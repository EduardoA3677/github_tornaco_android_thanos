.class public final synthetic Llyiahf/vczjk/ja2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOO0:Llyiahf/vczjk/le3;

.field public final synthetic OooOOOO:Llyiahf/vczjk/a91;

.field public final synthetic OooOOOo:Llyiahf/vczjk/a91;

.field public final synthetic OooOOo:Llyiahf/vczjk/qj8;

.field public final synthetic OooOOo0:Llyiahf/vczjk/a91;

.field public final synthetic OooOOoo:J

.field public final synthetic OooOo:Llyiahf/vczjk/ab2;

.field public final synthetic OooOo0:J

.field public final synthetic OooOo00:F

.field public final synthetic OooOo0O:J

.field public final synthetic OooOo0o:J

.field public final synthetic OooOoO:I

.field public final synthetic OooOoO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/qj8;JFJJJLlyiahf/vczjk/ab2;II)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ja2;->OooOOO0:Llyiahf/vczjk/le3;

    iput-object p2, p0, Llyiahf/vczjk/ja2;->OooOOO:Llyiahf/vczjk/a91;

    iput-object p3, p0, Llyiahf/vczjk/ja2;->OooOOOO:Llyiahf/vczjk/a91;

    iput-object p4, p0, Llyiahf/vczjk/ja2;->OooOOOo:Llyiahf/vczjk/a91;

    iput-object p5, p0, Llyiahf/vczjk/ja2;->OooOOo0:Llyiahf/vczjk/a91;

    iput-object p6, p0, Llyiahf/vczjk/ja2;->OooOOo:Llyiahf/vczjk/qj8;

    iput-wide p7, p0, Llyiahf/vczjk/ja2;->OooOOoo:J

    iput p9, p0, Llyiahf/vczjk/ja2;->OooOo00:F

    iput-wide p10, p0, Llyiahf/vczjk/ja2;->OooOo0:J

    iput-wide p12, p0, Llyiahf/vczjk/ja2;->OooOo0O:J

    iput-wide p14, p0, Llyiahf/vczjk/ja2;->OooOo0o:J

    move-object/from16 p1, p16

    iput-object p1, p0, Llyiahf/vczjk/ja2;->OooOo:Llyiahf/vczjk/ab2;

    move/from16 p1, p17

    iput p1, p0, Llyiahf/vczjk/ja2;->OooOoO0:I

    move/from16 p1, p18

    iput p1, p0, Llyiahf/vczjk/ja2;->OooOoO:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    move-object/from16 v0, p0

    move-object/from16 v17, p1

    check-cast v17, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Integer;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v1, v0, Llyiahf/vczjk/ja2;->OooOoO0:I

    or-int/lit8 v1, v1, 0x1

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v18

    iget-object v2, v0, Llyiahf/vczjk/ja2;->OooOOO:Llyiahf/vczjk/a91;

    iget-object v1, v0, Llyiahf/vczjk/ja2;->OooOo:Llyiahf/vczjk/ab2;

    iget v3, v0, Llyiahf/vczjk/ja2;->OooOoO:I

    move-object/from16 v16, v1

    iget-object v1, v0, Llyiahf/vczjk/ja2;->OooOOO0:Llyiahf/vczjk/le3;

    move/from16 v19, v3

    iget-object v3, v0, Llyiahf/vczjk/ja2;->OooOOOO:Llyiahf/vczjk/a91;

    iget-object v4, v0, Llyiahf/vczjk/ja2;->OooOOOo:Llyiahf/vczjk/a91;

    iget-object v5, v0, Llyiahf/vczjk/ja2;->OooOOo0:Llyiahf/vczjk/a91;

    iget-object v6, v0, Llyiahf/vczjk/ja2;->OooOOo:Llyiahf/vczjk/qj8;

    iget-wide v7, v0, Llyiahf/vczjk/ja2;->OooOOoo:J

    iget v9, v0, Llyiahf/vczjk/ja2;->OooOo00:F

    iget-wide v10, v0, Llyiahf/vczjk/ja2;->OooOo0:J

    iget-wide v12, v0, Llyiahf/vczjk/ja2;->OooOo0O:J

    iget-wide v14, v0, Llyiahf/vczjk/ja2;->OooOo0o:J

    invoke-static/range {v1 .. v19}, Llyiahf/vczjk/zsa;->OooOOo0(Llyiahf/vczjk/le3;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/a91;Llyiahf/vczjk/qj8;JFJJJLlyiahf/vczjk/ab2;Llyiahf/vczjk/rf1;II)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
