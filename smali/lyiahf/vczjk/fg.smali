.class public final Llyiahf/vczjk/fg;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $colorFilter:Llyiahf/vczjk/p21;

.field final synthetic $handleImage:Llyiahf/vczjk/lu3;

.field final synthetic $iconVisible:Llyiahf/vczjk/le3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/le3;"
        }
    .end annotation
.end field

.field final synthetic $isLeft:Z


# direct methods
.method public constructor <init>(Llyiahf/vczjk/le3;ZLlyiahf/vczjk/lu3;Llyiahf/vczjk/fd0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fg;->$iconVisible:Llyiahf/vczjk/le3;

    iput-boolean p2, p0, Llyiahf/vczjk/fg;->$isLeft:Z

    iput-object p3, p0, Llyiahf/vczjk/fg;->$handleImage:Llyiahf/vczjk/lu3;

    iput-object p4, p0, Llyiahf/vczjk/fg;->$colorFilter:Llyiahf/vczjk/p21;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    check-cast p1, Llyiahf/vczjk/mm1;

    check-cast p1, Llyiahf/vczjk/to4;

    invoke-virtual {p1}, Llyiahf/vczjk/to4;->OooO00o()V

    iget-object v0, p0, Llyiahf/vczjk/fg;->$iconVisible:Llyiahf/vczjk/le3;

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    iget-boolean v0, p0, Llyiahf/vczjk/fg;->$isLeft:Z

    iget-object p1, p1, Llyiahf/vczjk/to4;->OooOOO0:Llyiahf/vczjk/gq0;

    if-eqz v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/fg;->$handleImage:Llyiahf/vczjk/lu3;

    iget-object v1, p0, Llyiahf/vczjk/fg;->$colorFilter:Llyiahf/vczjk/p21;

    invoke-interface {p1}, Llyiahf/vczjk/hg2;->o00o0O()J

    move-result-wide v2

    iget-object v4, p1, Llyiahf/vczjk/gq0;->OooOOO:Llyiahf/vczjk/uqa;

    invoke-virtual {v4}, Llyiahf/vczjk/uqa;->OooOo00()J

    move-result-wide v5

    invoke-virtual {v4}, Llyiahf/vczjk/uqa;->OooOOOo()Llyiahf/vczjk/eq0;

    move-result-object v7

    invoke-interface {v7}, Llyiahf/vczjk/eq0;->OooO0oO()V

    :try_start_0
    iget-object v7, v4, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/vz5;

    const/high16 v8, -0x40800000    # -1.0f

    const/high16 v9, 0x3f800000    # 1.0f

    invoke-virtual {v7, v8, v9, v2, v3}, Llyiahf/vczjk/vz5;->OooOOo0(FFJ)V

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/gq0;->OooO0Oo(Llyiahf/vczjk/lu3;Llyiahf/vczjk/p21;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-static {v4, v5, v6}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    goto :goto_0

    :catchall_0
    move-exception p1

    invoke-static {v4, v5, v6}, Llyiahf/vczjk/ix8;->OooOo0O(Llyiahf/vczjk/uqa;J)V

    throw p1

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/fg;->$handleImage:Llyiahf/vczjk/lu3;

    iget-object v1, p0, Llyiahf/vczjk/fg;->$colorFilter:Llyiahf/vczjk/p21;

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/gq0;->OooO0Oo(Llyiahf/vczjk/lu3;Llyiahf/vczjk/p21;)V

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
