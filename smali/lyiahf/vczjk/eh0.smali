.class public final Llyiahf/vczjk/eh0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $boxHeight:Llyiahf/vczjk/fl7;

.field final synthetic $boxWidth:Llyiahf/vczjk/fl7;

.field final synthetic $measurables:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Llyiahf/vczjk/ef5;",
            ">;"
        }
    .end annotation
.end field

.field final synthetic $placeables:[Llyiahf/vczjk/ow6;

.field final synthetic $this_measure:Llyiahf/vczjk/nf5;

.field final synthetic this$0:Llyiahf/vczjk/fh0;


# direct methods
.method public constructor <init>([Llyiahf/vczjk/ow6;Ljava/util/List;Llyiahf/vczjk/nf5;Llyiahf/vczjk/fl7;Llyiahf/vczjk/fl7;Llyiahf/vczjk/fh0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/eh0;->$placeables:[Llyiahf/vczjk/ow6;

    iput-object p2, p0, Llyiahf/vczjk/eh0;->$measurables:Ljava/util/List;

    iput-object p3, p0, Llyiahf/vczjk/eh0;->$this_measure:Llyiahf/vczjk/nf5;

    iput-object p4, p0, Llyiahf/vczjk/eh0;->$boxWidth:Llyiahf/vczjk/fl7;

    iput-object p5, p0, Llyiahf/vczjk/eh0;->$boxHeight:Llyiahf/vczjk/fl7;

    iput-object p6, p0, Llyiahf/vczjk/eh0;->this$0:Llyiahf/vczjk/fh0;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/nw6;

    iget-object v8, v0, Llyiahf/vczjk/eh0;->$placeables:[Llyiahf/vczjk/ow6;

    iget-object v9, v0, Llyiahf/vczjk/eh0;->$measurables:Ljava/util/List;

    iget-object v10, v0, Llyiahf/vczjk/eh0;->$this_measure:Llyiahf/vczjk/nf5;

    iget-object v11, v0, Llyiahf/vczjk/eh0;->$boxWidth:Llyiahf/vczjk/fl7;

    iget-object v12, v0, Llyiahf/vczjk/eh0;->$boxHeight:Llyiahf/vczjk/fl7;

    iget-object v13, v0, Llyiahf/vczjk/eh0;->this$0:Llyiahf/vczjk/fh0;

    array-length v14, v8

    const/4 v2, 0x0

    move v15, v2

    :goto_0
    if-ge v15, v14, :cond_0

    aget-object v3, v8, v15

    add-int/lit8 v16, v2, 0x1

    const-string v4, "null cannot be cast to non-null type androidx.compose.ui.layout.Placeable"

    invoke-static {v3, v4}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v9, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/ef5;

    invoke-interface {v10}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v4

    iget v5, v11, Llyiahf/vczjk/fl7;->element:I

    iget v6, v12, Llyiahf/vczjk/fl7;->element:I

    iget-object v7, v13, Llyiahf/vczjk/fh0;->OooO00o:Llyiahf/vczjk/o4;

    move-object/from16 v17, v3

    move-object v3, v2

    move-object/from16 v2, v17

    invoke-static/range {v1 .. v7}, Llyiahf/vczjk/ch0;->OooO0O0(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;Llyiahf/vczjk/ef5;Llyiahf/vczjk/yn4;IILlyiahf/vczjk/o4;)V

    add-int/lit8 v15, v15, 0x1

    move/from16 v2, v16

    goto :goto_0

    :cond_0
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method
