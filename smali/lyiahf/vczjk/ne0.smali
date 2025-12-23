.class public final Llyiahf/vczjk/ne0;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $cacheImageBitmap:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field final synthetic $colorFilter:Llyiahf/vczjk/p21;

.field final synthetic $pathBounds:Llyiahf/vczjk/wj7;

.field final synthetic $pathBoundsSize:J


# direct methods
.method public constructor <init>(Llyiahf/vczjk/wj7;Llyiahf/vczjk/hl7;JLlyiahf/vczjk/fd0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ne0;->$pathBounds:Llyiahf/vczjk/wj7;

    iput-object p2, p0, Llyiahf/vczjk/ne0;->$cacheImageBitmap:Llyiahf/vczjk/hl7;

    iput-wide p3, p0, Llyiahf/vczjk/ne0;->$pathBoundsSize:J

    iput-object p5, p0, Llyiahf/vczjk/ne0;->$colorFilter:Llyiahf/vczjk/p21;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    check-cast p1, Llyiahf/vczjk/mm1;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/to4;

    invoke-virtual {v0}, Llyiahf/vczjk/to4;->OooO00o()V

    iget-object p1, p0, Llyiahf/vczjk/ne0;->$pathBounds:Llyiahf/vczjk/wj7;

    iget v10, p1, Llyiahf/vczjk/wj7;->OooO00o:F

    iget-object v1, p0, Llyiahf/vczjk/ne0;->$cacheImageBitmap:Llyiahf/vczjk/hl7;

    iget-wide v2, p0, Llyiahf/vczjk/ne0;->$pathBoundsSize:J

    iget-object v7, p0, Llyiahf/vczjk/ne0;->$colorFilter:Llyiahf/vczjk/p21;

    iget-object v11, v0, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    iget-object v4, v11, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    iget-object v4, v4, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/vz5;

    iget p1, p1, Llyiahf/vczjk/wj7;->OooO0O0:F

    invoke-virtual {v4, v10, p1}, Llyiahf/vczjk/vz5;->OooOOo(FF)V

    :try_start_0
    iget-object v1, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/lu3;

    const-wide/16 v4, 0x0

    const/4 v6, 0x0

    const/4 v8, 0x0

    const/16 v9, 0x37a

    invoke-static/range {v0 .. v9}, Llyiahf/vczjk/hg2;->OoooooO(Llyiahf/vczjk/hg2;Llyiahf/vczjk/lu3;JJFLlyiahf/vczjk/p21;II)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    iget-object v0, v11, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    iget-object v0, v0, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/vz5;

    neg-float v1, v10

    neg-float p1, p1

    invoke-virtual {v0, v1, p1}, Llyiahf/vczjk/vz5;->OooOOo(FF)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :catchall_0
    move-exception v0

    iget-object v1, v11, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    iget-object v1, v1, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/vz5;

    neg-float v2, v10

    neg-float p1, p1

    invoke-virtual {v1, v2, p1}, Llyiahf/vczjk/vz5;->OooOOo(FF)V

    throw v0
.end method
