.class public final synthetic Llyiahf/vczjk/cm9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/hl5;

.field public final synthetic OooOOO0:Llyiahf/vczjk/an;

.field public final synthetic OooOOOO:J

.field public final synthetic OooOOOo:J

.field public final synthetic OooOOo:J

.field public final synthetic OooOOo0:J

.field public final synthetic OooOOoo:I

.field public final synthetic OooOo:Llyiahf/vczjk/oe3;

.field public final synthetic OooOo0:I

.field public final synthetic OooOo00:Z

.field public final synthetic OooOo0O:I

.field public final synthetic OooOo0o:Llyiahf/vczjk/bn2;

.field public final synthetic OooOoO:I

.field public final synthetic OooOoO0:Llyiahf/vczjk/rn9;

.field public final synthetic OooOoOO:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/an;Llyiahf/vczjk/hl5;JJJJIZIILlyiahf/vczjk/bn2;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;II)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/cm9;->OooOOO0:Llyiahf/vczjk/an;

    iput-object p2, p0, Llyiahf/vczjk/cm9;->OooOOO:Llyiahf/vczjk/hl5;

    iput-wide p3, p0, Llyiahf/vczjk/cm9;->OooOOOO:J

    iput-wide p5, p0, Llyiahf/vczjk/cm9;->OooOOOo:J

    iput-wide p7, p0, Llyiahf/vczjk/cm9;->OooOOo0:J

    iput-wide p9, p0, Llyiahf/vczjk/cm9;->OooOOo:J

    iput p11, p0, Llyiahf/vczjk/cm9;->OooOOoo:I

    iput-boolean p12, p0, Llyiahf/vczjk/cm9;->OooOo00:Z

    iput p13, p0, Llyiahf/vczjk/cm9;->OooOo0:I

    iput p14, p0, Llyiahf/vczjk/cm9;->OooOo0O:I

    iput-object p15, p0, Llyiahf/vczjk/cm9;->OooOo0o:Llyiahf/vczjk/bn2;

    move-object/from16 p1, p16

    iput-object p1, p0, Llyiahf/vczjk/cm9;->OooOo:Llyiahf/vczjk/oe3;

    move-object/from16 p1, p17

    iput-object p1, p0, Llyiahf/vczjk/cm9;->OooOoO0:Llyiahf/vczjk/rn9;

    move/from16 p1, p18

    iput p1, p0, Llyiahf/vczjk/cm9;->OooOoO:I

    move/from16 p1, p19

    iput p1, p0, Llyiahf/vczjk/cm9;->OooOoOO:I

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 22

    move-object/from16 v0, p0

    move-object/from16 v18, p1

    check-cast v18, Llyiahf/vczjk/rf1;

    move-object/from16 v1, p2

    check-cast v1, Ljava/lang/Integer;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v1, v0, Llyiahf/vczjk/cm9;->OooOoO:I

    or-int/lit8 v1, v1, 0x1

    invoke-static {v1}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result v19

    iget-object v1, v0, Llyiahf/vczjk/cm9;->OooOOO0:Llyiahf/vczjk/an;

    iget-object v2, v0, Llyiahf/vczjk/cm9;->OooOoO0:Llyiahf/vczjk/rn9;

    iget v3, v0, Llyiahf/vczjk/cm9;->OooOoOO:I

    move-object/from16 v17, v2

    iget-object v2, v0, Llyiahf/vczjk/cm9;->OooOOO:Llyiahf/vczjk/hl5;

    move/from16 v20, v3

    iget-wide v3, v0, Llyiahf/vczjk/cm9;->OooOOOO:J

    iget-wide v5, v0, Llyiahf/vczjk/cm9;->OooOOOo:J

    iget-wide v7, v0, Llyiahf/vczjk/cm9;->OooOOo0:J

    iget-wide v9, v0, Llyiahf/vczjk/cm9;->OooOOo:J

    iget v11, v0, Llyiahf/vczjk/cm9;->OooOOoo:I

    iget-boolean v12, v0, Llyiahf/vczjk/cm9;->OooOo00:Z

    iget v13, v0, Llyiahf/vczjk/cm9;->OooOo0:I

    iget v14, v0, Llyiahf/vczjk/cm9;->OooOo0O:I

    iget-object v15, v0, Llyiahf/vczjk/cm9;->OooOo0o:Llyiahf/vczjk/bn2;

    move-object/from16 v16, v1

    iget-object v1, v0, Llyiahf/vczjk/cm9;->OooOo:Llyiahf/vczjk/oe3;

    move-object/from16 v21, v16

    move-object/from16 v16, v1

    move-object/from16 v1, v21

    invoke-static/range {v1 .. v20}, Llyiahf/vczjk/gm9;->OooO0OO(Llyiahf/vczjk/an;Llyiahf/vczjk/hl5;JJJJIZIILlyiahf/vczjk/bn2;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rn9;Llyiahf/vczjk/rf1;II)V

    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
