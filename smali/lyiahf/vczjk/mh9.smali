.class public final Llyiahf/vczjk/mh9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $linkFound:Llyiahf/vczjk/dl7;

.field final synthetic $linkRange:Llyiahf/vczjk/zm;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/zm;"
        }
    .end annotation
.end field

.field final synthetic $newStyle:Llyiahf/vczjk/dy8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dl7;Llyiahf/vczjk/zm;Llyiahf/vczjk/dy8;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/mh9;->$linkFound:Llyiahf/vczjk/dl7;

    iput-object p2, p0, Llyiahf/vczjk/mh9;->$linkRange:Llyiahf/vczjk/zm;

    iput-object p3, p0, Llyiahf/vczjk/mh9;->$newStyle:Llyiahf/vczjk/dy8;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 26

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/zm;

    iget-object v2, v0, Llyiahf/vczjk/mh9;->$linkFound:Llyiahf/vczjk/dl7;

    iget-boolean v2, v2, Llyiahf/vczjk/dl7;->element:Z

    if-eqz v2, :cond_1

    iget-object v2, v1, Llyiahf/vczjk/zm;->OooO00o:Ljava/lang/Object;

    instance-of v2, v2, Llyiahf/vczjk/dy8;

    if-eqz v2, :cond_1

    iget-object v2, v0, Llyiahf/vczjk/mh9;->$linkRange:Llyiahf/vczjk/zm;

    iget v3, v2, Llyiahf/vczjk/zm;->OooO0O0:I

    iget v4, v1, Llyiahf/vczjk/zm;->OooO0O0:I

    if-ne v4, v3, :cond_1

    iget v2, v2, Llyiahf/vczjk/zm;->OooO0OO:I

    iget v3, v1, Llyiahf/vczjk/zm;->OooO0OO:I

    if-ne v3, v2, :cond_1

    new-instance v2, Llyiahf/vczjk/zm;

    iget-object v5, v0, Llyiahf/vczjk/mh9;->$newStyle:Llyiahf/vczjk/dy8;

    if-nez v5, :cond_0

    new-instance v6, Llyiahf/vczjk/dy8;

    const/16 v24, 0x0

    const v25, 0xffff

    const-wide/16 v7, 0x0

    const-wide/16 v9, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const/4 v14, 0x0

    const/4 v15, 0x0

    const-wide/16 v16, 0x0

    const/16 v18, 0x0

    const/16 v19, 0x0

    const/16 v20, 0x0

    const-wide/16 v21, 0x0

    const/16 v23, 0x0

    invoke-direct/range {v6 .. v25}, Llyiahf/vczjk/dy8;-><init>(JJLlyiahf/vczjk/ib3;Llyiahf/vczjk/cb3;Llyiahf/vczjk/db3;Llyiahf/vczjk/ba3;Ljava/lang/String;JLlyiahf/vczjk/f90;Llyiahf/vczjk/ll9;Llyiahf/vczjk/e45;JLlyiahf/vczjk/vh9;Llyiahf/vczjk/ij8;I)V

    move-object v5, v6

    :cond_0
    invoke-direct {v2, v4, v3, v5}, Llyiahf/vczjk/zm;-><init>(IILjava/lang/Object;)V

    goto :goto_0

    :cond_1
    move-object v2, v1

    :goto_0
    iget-object v3, v0, Llyiahf/vczjk/mh9;->$linkFound:Llyiahf/vczjk/dl7;

    iget-object v4, v0, Llyiahf/vczjk/mh9;->$linkRange:Llyiahf/vczjk/zm;

    invoke-static {v4, v1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    iput-boolean v1, v3, Llyiahf/vczjk/dl7;->element:Z

    return-object v2
.end method
