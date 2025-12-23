.class public final Llyiahf/vczjk/nc;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $colorFilter:Llyiahf/vczjk/p21;

.field final synthetic $imageBitmap:Llyiahf/vczjk/lu3;

.field final synthetic $radius:F


# direct methods
.method public constructor <init>(FLlyiahf/vczjk/lu3;Llyiahf/vczjk/fd0;)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/nc;->$radius:F

    iput-object p2, p0, Llyiahf/vczjk/nc;->$imageBitmap:Llyiahf/vczjk/lu3;

    iput-object p3, p0, Llyiahf/vczjk/nc;->$colorFilter:Llyiahf/vczjk/p21;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Llyiahf/vczjk/mm1;

    check-cast p1, Llyiahf/vczjk/to4;

    invoke-virtual {p1}, Llyiahf/vczjk/to4;->OooO00o()V

    iget v0, p0, Llyiahf/vczjk/nc;->$radius:F

    iget-object v1, p0, Llyiahf/vczjk/nc;->$imageBitmap:Llyiahf/vczjk/lu3;

    iget-object v2, p0, Llyiahf/vczjk/nc;->$colorFilter:Llyiahf/vczjk/p21;

    iget-object p1, p1, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    iget-object v3, p1, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    invoke-virtual {v3}, Llyiahf/vczjk/uqa;->OooOo00()J

    move-result-wide v4

    invoke-virtual {v3}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v6

    invoke-interface {v6}, Llyiahf/vczjk/eq0;->OooO0oO()V

    :try_start_0
    iget-object v6, v3, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v6, Llyiahf/vczjk/vz5;

    const/4 v7, 0x0

    invoke-virtual {v6, v0, v7}, Llyiahf/vczjk/vz5;->OooOOo(FF)V

    const/high16 v0, 0x42340000    # 45.0f

    const-wide/16 v7, 0x0

    invoke-virtual {v6, v0, v7, v8}, Llyiahf/vczjk/vz5;->OooOOOo(FJ)V

    invoke-virtual {p1, v1, v2}, Llyiahf/vczjk/gq0;->OooO0Oo(Llyiahf/vczjk/lu3;Llyiahf/vczjk/p21;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-static {v3, v4, v5}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :catchall_0
    move-exception p1

    invoke-static {v3, v4, v5}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    throw p1
.end method
