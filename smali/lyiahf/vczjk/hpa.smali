.class public final Llyiahf/vczjk/hpa;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/sy4;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/as6;

.field public final synthetic OooOOO0:Llyiahf/vczjk/to1;

.field public final synthetic OooOOOO:Llyiahf/vczjk/oj7;

.field public final synthetic OooOOOo:Llyiahf/vczjk/hl7;

.field public final synthetic OooOOo0:Landroid/view/View;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/to1;Llyiahf/vczjk/as6;Llyiahf/vczjk/oj7;Llyiahf/vczjk/hl7;Landroid/view/View;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/hpa;->OooOOO0:Llyiahf/vczjk/to1;

    iput-object p2, p0, Llyiahf/vczjk/hpa;->OooOOO:Llyiahf/vczjk/as6;

    iput-object p3, p0, Llyiahf/vczjk/hpa;->OooOOOO:Llyiahf/vczjk/oj7;

    iput-object p4, p0, Llyiahf/vczjk/hpa;->OooOOOo:Llyiahf/vczjk/hl7;

    iput-object p5, p0, Llyiahf/vczjk/hpa;->OooOOo0:Landroid/view/View;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/uy4;Llyiahf/vczjk/iy4;)V
    .locals 10

    sget-object v0, Llyiahf/vczjk/epa;->OooO00o:[I

    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    move-result p2

    aget p2, v0, p2

    const/4 v0, 0x0

    const/4 v1, 0x1

    if-eq p2, v1, :cond_8

    const/4 p1, 0x2

    if-eq p2, p1, :cond_2

    const/4 p1, 0x3

    if-eq p2, p1, :cond_1

    const/4 p1, 0x4

    if-eq p2, p1, :cond_0

    goto/16 :goto_4

    :cond_0
    iget-object p1, p0, Llyiahf/vczjk/hpa;->OooOOOO:Llyiahf/vczjk/oj7;

    invoke-virtual {p1}, Llyiahf/vczjk/oj7;->OooOo00()V

    return-void

    :cond_1
    iget-object p1, p0, Llyiahf/vczjk/hpa;->OooOOOO:Llyiahf/vczjk/oj7;

    iget-object p2, p1, Llyiahf/vczjk/oj7;->OooO0O0:Ljava/lang/Object;

    monitor-enter p2

    :try_start_0
    iput-boolean v1, p1, Llyiahf/vczjk/oj7;->OooOOoo:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    monitor-exit p2

    return-void

    :catchall_0
    move-exception v0

    move-object p1, v0

    monitor-exit p2

    throw p1

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/hpa;->OooOOO:Llyiahf/vczjk/as6;

    const/4 p2, 0x0

    if-eqz p1, :cond_5

    iget-object p1, p1, Llyiahf/vczjk/as6;->OooOOO:Llyiahf/vczjk/cn4;

    iget-object v2, p1, Llyiahf/vczjk/cn4;->OooO00o:Ljava/lang/Object;

    monitor-enter v2

    :try_start_1
    iget-object v3, p1, Llyiahf/vczjk/cn4;->OooO00o:Ljava/lang/Object;

    monitor-enter v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :try_start_2
    iget-boolean v4, p1, Llyiahf/vczjk/cn4;->OooO0Oo:Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    :try_start_3
    monitor-exit v3
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    if-eqz v4, :cond_3

    monitor-exit v2

    goto :goto_2

    :cond_3
    :try_start_4
    iget-object v3, p1, Llyiahf/vczjk/cn4;->OooO0O0:Ljava/util/ArrayList;

    iget-object v4, p1, Llyiahf/vczjk/cn4;->OooO0OO:Ljava/util/ArrayList;

    iput-object v4, p1, Llyiahf/vczjk/cn4;->OooO0O0:Ljava/util/ArrayList;

    iput-object v3, p1, Llyiahf/vczjk/cn4;->OooO0OO:Ljava/util/ArrayList;

    iput-boolean v1, p1, Llyiahf/vczjk/cn4;->OooO0Oo:Z

    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    move-result p1

    move v1, p2

    :goto_0
    if-ge v1, p1, :cond_4

    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Llyiahf/vczjk/yo1;

    sget-object v5, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-interface {v4, v5}, Llyiahf/vczjk/yo1;->resumeWith(Ljava/lang/Object;)V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :catchall_1
    move-exception v0

    move-object p1, v0

    goto :goto_1

    :cond_4
    invoke-virtual {v3}, Ljava/util/ArrayList;->clear()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    monitor-exit v2

    goto :goto_2

    :catchall_2
    move-exception v0

    move-object p1, v0

    :try_start_5
    monitor-exit v3

    throw p1
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    :goto_1
    monitor-exit v2

    throw p1

    :cond_5
    :goto_2
    iget-object p1, p0, Llyiahf/vczjk/hpa;->OooOOOO:Llyiahf/vczjk/oj7;

    iget-object v1, p1, Llyiahf/vczjk/oj7;->OooO0O0:Ljava/lang/Object;

    monitor-enter v1

    :try_start_6
    iget-boolean v2, p1, Llyiahf/vczjk/oj7;->OooOOoo:Z

    if-eqz v2, :cond_6

    iput-boolean p2, p1, Llyiahf/vczjk/oj7;->OooOOoo:Z

    invoke-virtual {p1}, Llyiahf/vczjk/oj7;->OooOo0()Llyiahf/vczjk/wp0;

    move-result-object v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    goto :goto_3

    :catchall_3
    move-exception v0

    move-object p1, v0

    goto :goto_5

    :cond_6
    :goto_3
    monitor-exit v1

    if-eqz v0, :cond_7

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    check-cast v0, Llyiahf/vczjk/yp0;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    :cond_7
    :goto_4
    return-void

    :goto_5
    monitor-exit v1

    throw p1

    :cond_8
    iget-object p2, p0, Llyiahf/vczjk/hpa;->OooOOO0:Llyiahf/vczjk/to1;

    sget-object v2, Llyiahf/vczjk/as1;->OooOOOo:Llyiahf/vczjk/as1;

    new-instance v3, Llyiahf/vczjk/gpa;

    iget-object v4, p0, Llyiahf/vczjk/hpa;->OooOOOo:Llyiahf/vczjk/hl7;

    iget-object v5, p0, Llyiahf/vczjk/hpa;->OooOOOO:Llyiahf/vczjk/oj7;

    iget-object v8, p0, Llyiahf/vczjk/hpa;->OooOOo0:Landroid/view/View;

    const/4 v9, 0x0

    move-object v7, p0

    move-object v6, p1

    invoke-direct/range {v3 .. v9}, Llyiahf/vczjk/gpa;-><init>(Llyiahf/vczjk/hl7;Llyiahf/vczjk/oj7;Llyiahf/vczjk/uy4;Llyiahf/vczjk/hpa;Landroid/view/View;Llyiahf/vczjk/yo1;)V

    invoke-static {p2, v0, v2, v3, v1}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method
