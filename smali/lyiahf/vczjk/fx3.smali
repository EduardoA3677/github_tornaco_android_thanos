.class public final Llyiahf/vczjk/fx3;
.super Llyiahf/vczjk/i80;
.source "SourceFile"


# instance fields
.field public Oooo:Llyiahf/vczjk/le3;

.field public Oooo0oo:Llyiahf/vczjk/le3;

.field public final OoooO:[F

.field public OoooO0:Llyiahf/vczjk/le3;

.field public OoooO00:Llyiahf/vczjk/le3;

.field public OoooO0O:F

.field public final OoooOO0:Llyiahf/vczjk/rm0;


# direct methods
.method public constructor <init>(FFFFJJLlyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/h79;Llyiahf/vczjk/h79;)V
    .locals 10

    move-object v0, p0

    move v7, p2

    move v8, p3

    move v9, p4

    move-wide v1, p5

    move-wide/from16 v3, p7

    move-object/from16 v5, p13

    move-object/from16 v6, p14

    invoke-direct/range {v0 .. v9}, Llyiahf/vczjk/i80;-><init>(JJLlyiahf/vczjk/h79;Llyiahf/vczjk/h79;FFF)V

    move-object/from16 p2, p9

    iput-object p2, p0, Llyiahf/vczjk/fx3;->Oooo0oo:Llyiahf/vczjk/le3;

    move-object/from16 p2, p10

    iput-object p2, p0, Llyiahf/vczjk/fx3;->Oooo:Llyiahf/vczjk/le3;

    move-object/from16 p2, p11

    iput-object p2, p0, Llyiahf/vczjk/fx3;->OoooO00:Llyiahf/vczjk/le3;

    move-object/from16 p2, p12

    iput-object p2, p0, Llyiahf/vczjk/fx3;->OoooO0:Llyiahf/vczjk/le3;

    const/4 p2, 0x0

    cmpg-float p3, p1, p2

    if-gez p3, :cond_0

    move p1, p2

    :cond_0
    const/high16 p2, 0x3f800000    # 1.0f

    cmpl-float p3, p1, p2

    if-lez p3, :cond_1

    move p1, p2

    :cond_1
    iput p1, p0, Llyiahf/vczjk/fx3;->OoooO0O:F

    const/4 p1, 0x4

    new-array p1, p1, [F

    fill-array-data p1, :array_0

    iput-object p1, p0, Llyiahf/vczjk/fx3;->OoooO:[F

    new-instance p1, Llyiahf/vczjk/ex3;

    const/4 p2, 0x0

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/ex3;-><init>(Llyiahf/vczjk/fx3;I)V

    new-instance p2, Llyiahf/vczjk/rm0;

    new-instance p3, Llyiahf/vczjk/tm0;

    invoke-direct {p3}, Llyiahf/vczjk/tm0;-><init>()V

    invoke-direct {p2, p3, p1}, Llyiahf/vczjk/rm0;-><init>(Llyiahf/vczjk/tm0;Llyiahf/vczjk/oe3;)V

    invoke-virtual {p0, p2}, Llyiahf/vczjk/m52;->o00000OO(Llyiahf/vczjk/l52;)Llyiahf/vczjk/l52;

    iput-object p2, p0, Llyiahf/vczjk/fx3;->OoooOO0:Llyiahf/vczjk/rm0;

    return-void

    nop

    :array_0
    .array-data 4
        0x0
        0x0
        0x0
        0x0
    .end array-data
.end method


# virtual methods
.method public final o00000oO()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/fx3;->OoooOO0:Llyiahf/vczjk/rm0;

    invoke-virtual {v0}, Llyiahf/vczjk/rm0;->o00000OO()V

    return-void
.end method
