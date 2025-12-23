.class public Llyiahf/vczjk/tg7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/u96;
.implements Llyiahf/vczjk/ar8;
.implements Llyiahf/vczjk/ch5;
.implements Llyiahf/vczjk/q01;
.implements Llyiahf/vczjk/c17;
.implements Llyiahf/vczjk/z02;
.implements Llyiahf/vczjk/bja;
.implements Llyiahf/vczjk/du2;
.implements Llyiahf/vczjk/rv1;
.implements Llyiahf/vczjk/ho0;
.implements Llyiahf/vczjk/lb2;
.implements Llyiahf/vczjk/dh6;
.implements Llyiahf/vczjk/qg5;
.implements Llyiahf/vczjk/h52;


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/op3;


# instance fields
.field public OooOOO:Ljava/lang/Object;

.field public final synthetic OooOOO0:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/op3;

    const/16 v1, 0x1b

    invoke-direct {v0, v1}, Llyiahf/vczjk/op3;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/tg7;->OooOOOO:Llyiahf/vczjk/op3;

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, Llyiahf/vczjk/tg7;->OooOOO0:I

    packed-switch p1, :pswitch_data_0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void

    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance p1, Ljava/util/HashMap;

    const/4 v0, 0x3

    invoke-direct {p1, v0}, Ljava/util/HashMap;-><init>(I)V

    iput-object p1, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x14
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/view/GestureDetector$SimpleOnGestureListener;Landroid/os/Handler;)V
    .locals 1

    const/16 v0, 0xf

    iput v0, p0, Llyiahf/vczjk/tg7;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/vz5;

    invoke-direct {v0, p1, p2, p3}, Llyiahf/vczjk/vz5;-><init>(Landroid/content/Context;Landroid/view/GestureDetector$SimpleOnGestureListener;Landroid/os/Handler;)V

    iput-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroidx/work/impl/WorkDatabase;)V
    .locals 1

    const/16 v0, 0x10

    iput v0, p0, Llyiahf/vczjk/tg7;->OooOOO0:I

    const-string v0, "workDatabase"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/tg7;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/kha;Llyiahf/vczjk/hha;Llyiahf/vczjk/os1;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/tg7;->OooOOO0:I

    const-string v0, "store"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "factory"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "defaultCreationExtras"

    invoke-static {p3, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/pb7;

    invoke-direct {v0, p1, p2, p3}, Llyiahf/vczjk/pb7;-><init>(Llyiahf/vczjk/kha;Llyiahf/vczjk/hha;Llyiahf/vczjk/os1;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/yf4;)V
    .locals 1

    const/16 v0, 0xa

    iput v0, p0, Llyiahf/vczjk/tg7;->OooOOO0:I

    const-string v0, "container"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public OooO(Llyiahf/vczjk/pm;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/eh6;

    iget-object v0, v0, Llyiahf/vczjk/eh6;->OooOOOo:Llyiahf/vczjk/yn;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/yn;->Oooo00O(Llyiahf/vczjk/pm;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public OooO00o(Llyiahf/vczjk/v82;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public OooO0O0(Ljava/util/HashMap;)V
    .locals 5

    invoke-virtual {p1}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    return-void

    :cond_0
    invoke-virtual {p1}, Ljava/util/HashMap;->size()I

    move-result v1

    const/16 v2, 0x3e7

    if-le v1, v2, :cond_1

    new-instance v0, Llyiahf/vczjk/sg7;

    const/4 v1, 0x1

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/sg7;-><init>(Llyiahf/vczjk/tg7;I)V

    invoke-static {p1, v0}, Llyiahf/vczjk/xr6;->OooOOOO(Ljava/util/HashMap;Llyiahf/vczjk/oe3;)V

    return-void

    :cond_1
    const-string v1, "SELECT `progress`,`work_spec_id` FROM `WorkProgress` WHERE `work_spec_id` IN ("

    invoke-static {v1}, Llyiahf/vczjk/ii5;->OooOOOO(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-interface {v0}, Ljava/util/Set;->size()I

    move-result v2

    invoke-static {v2, v1}, Llyiahf/vczjk/xt6;->OooOo0O(ILjava/lang/StringBuilder;)V

    const-string v3, ")"

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v2, v1}, Llyiahf/vczjk/xu7;->OooOOOO(ILjava/lang/String;)Llyiahf/vczjk/xu7;

    move-result-object v1

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    const/4 v2, 0x1

    move v3, v2

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    invoke-virtual {v1, v3, v4}, Llyiahf/vczjk/xu7;->OooOOO0(ILjava/lang/String;)V

    add-int/2addr v3, v2

    goto :goto_0

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroidx/work/impl/WorkDatabase_Impl;

    const/4 v2, 0x0

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/u34;->OoooO0O(Llyiahf/vczjk/ru7;Llyiahf/vczjk/ia9;Z)Landroid/database/Cursor;

    move-result-object v0

    :try_start_0
    const-string v1, "work_spec_id"

    invoke-static {v0, v1}, Llyiahf/vczjk/cp7;->OooOo0O(Landroid/database/Cursor;Ljava/lang/String;)I

    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/4 v3, -0x1

    if-ne v1, v3, :cond_3

    invoke-interface {v0}, Landroid/database/Cursor;->close()V

    return-void

    :cond_3
    :goto_1
    :try_start_1
    invoke-interface {v0}, Landroid/database/Cursor;->moveToNext()Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {p1, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/ArrayList;

    if-eqz v3, :cond_3

    invoke-interface {v0, v2}, Landroid/database/Cursor;->getBlob(I)[B

    move-result-object v4

    invoke-static {v4}, Llyiahf/vczjk/mw1;->OooO00o([B)Llyiahf/vczjk/mw1;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_4
    invoke-interface {v0}, Landroid/database/Cursor;->close()V

    return-void

    :goto_2
    invoke-interface {v0}, Landroid/database/Cursor;->close()V

    throw p1
.end method

.method public OooO0OO(Ljava/io/Closeable;Ljava/lang/Throwable;Ljava/lang/Throwable;)V
    .locals 3

    if-ne p2, p3, :cond_0

    goto :goto_0

    :cond_0
    :try_start_0
    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/lang/reflect/Method;

    filled-new-array {p3}, [Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {v0, p2, v1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    return-void

    :catchall_0
    sget-object p2, Llyiahf/vczjk/l01;->OooO00o:Ljava/util/logging/Logger;

    sget-object v0, Ljava/util/logging/Level;->WARNING:Ljava/util/logging/Level;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Suppressing exception thrown when closing "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p2, v0, p1, p3}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    :goto_0
    return-void
.end method

.method public OooO0Oo(Llyiahf/vczjk/sg5;Llyiahf/vczjk/dh5;)V
    .locals 0

    iget-object p2, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/ir0;

    iget-object p2, p2, Llyiahf/vczjk/ir0;->OooOOoo:Landroid/os/Handler;

    invoke-virtual {p2, p1}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    return-void
.end method

.method public OooO0o(Llyiahf/vczjk/rf3;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p2, Llyiahf/vczjk/z8a;

    new-instance p2, Llyiahf/vczjk/bg4;

    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/yf4;

    invoke-direct {p2, v0, p1}, Llyiahf/vczjk/bg4;-><init>(Llyiahf/vczjk/yf4;Llyiahf/vczjk/rf3;)V

    return-object p2
.end method

.method public OooO0o0(Ljava/lang/String;JLlyiahf/vczjk/oo0oO0;)V
    .locals 7

    const-string v0, "ruleName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/d52;

    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lnow/fortuitous/profile/ProfileService;

    invoke-virtual {v0}, Llyiahf/vczjk/td9;->OooOOO0()Landroid/content/Context;

    move-result-object v2

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v3

    new-instance v5, Ljava/lang/StringBuilder;

    const-string v6, "Profile-Rule-"

    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v5, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string p1, "-"

    invoke-virtual {v5, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v5, v3, v4}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    new-instance v5, Llyiahf/vczjk/q87;

    const/4 p1, 0x2

    invoke-direct {v5, v0, p1}, Llyiahf/vczjk/q87;-><init>(Lnow/fortuitous/profile/ProfileService;I)V

    new-instance v6, Llyiahf/vczjk/w45;

    const/16 p1, 0xd

    invoke-direct {v6, p4, p1}, Llyiahf/vczjk/w45;-><init>(Ljava/lang/Object;I)V

    const/4 v4, 0x1

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/d52;-><init>(Landroid/content/Context;Ljava/lang/String;ZLlyiahf/vczjk/le3;Llyiahf/vczjk/oe3;)V

    invoke-virtual {v1, p2, p3}, Llyiahf/vczjk/d52;->OooO0O0(J)V

    return-void
.end method

.method public OooO0oO(Ljava/lang/Object;)Ljava/lang/Iterable;
    .locals 4

    check-cast p1, Llyiahf/vczjk/by0;

    invoke-interface {p1}, Llyiahf/vczjk/gz0;->OooOo0o()Llyiahf/vczjk/n3a;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/n3a;->OooO0O0()Ljava/util/Collection;

    move-result-object p1

    const-string v0, "getSupertypes(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Ljava/lang/Iterable;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_5

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/uk4;

    invoke-virtual {v1}, Llyiahf/vczjk/uk4;->o000000()Llyiahf/vczjk/n3a;

    move-result-object v1

    invoke-interface {v1}, Llyiahf/vczjk/n3a;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v1

    const/4 v2, 0x0

    if-eqz v1, :cond_1

    invoke-interface {v1}, Llyiahf/vczjk/gz0;->OooO00o()Llyiahf/vczjk/gz0;

    move-result-object v1

    goto :goto_1

    :cond_1
    move-object v1, v2

    :goto_1
    instance-of v3, v1, Llyiahf/vczjk/by0;

    if-eqz v3, :cond_2

    check-cast v1, Llyiahf/vczjk/by0;

    goto :goto_2

    :cond_2
    move-object v1, v2

    :goto_2
    if-nez v1, :cond_3

    goto :goto_3

    :cond_3
    iget-object v2, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/nd4;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/nd4;->OooO00o(Llyiahf/vczjk/by0;)Llyiahf/vczjk/nr4;

    move-result-object v2

    if-eqz v2, :cond_4

    goto :goto_3

    :cond_4
    move-object v2, v1

    :goto_3
    if-eqz v2, :cond_0

    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_5
    return-object v0
.end method

.method public OooO0oo(Llyiahf/vczjk/yl5;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public OooOO0(Llyiahf/vczjk/fi7;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/j00;

    iget-object v0, v0, Llyiahf/vczjk/j00;->OooOOoo:Llyiahf/vczjk/s29;

    new-instance v1, Llyiahf/vczjk/i00;

    const/4 v2, 0x0

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/i00;-><init>(Llyiahf/vczjk/s29;I)V

    invoke-static {v1, p1}, Llyiahf/vczjk/rs;->OooOoO(Llyiahf/vczjk/f43;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public OooOO0O()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;

    iget v0, v0, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;->OooooOO:I

    return v0
.end method

.method public OooOO0o(Llyiahf/vczjk/ux0;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/tg7;->OooO0o(Llyiahf/vczjk/rf3;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public OooOOO(F)Z
    .locals 1

    const/4 v0, 0x0

    cmpl-float v0, p1, v0

    if-nez v0, :cond_0

    const/4 p1, 0x0

    return p1

    :cond_0
    invoke-virtual {p0}, Llyiahf/vczjk/tg7;->OooOo()V

    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroidx/core/widget/NestedScrollView;

    float-to-int p1, p1

    invoke-virtual {v0, p1}, Landroidx/core/widget/NestedScrollView;->OooOO0(I)V

    const/4 p1, 0x1

    return p1
.end method

.method public OooOOO0(Llyiahf/vczjk/sg5;Llyiahf/vczjk/dh5;)V
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ir0;

    iget-object v1, v0, Llyiahf/vczjk/ir0;->OooOOoo:Landroid/os/Handler;

    const/4 v2, 0x0

    invoke-virtual {v1, v2}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    iget-object v1, v0, Llyiahf/vczjk/ir0;->OooOo0:Ljava/util/ArrayList;

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v3

    const/4 v4, 0x0

    :goto_0
    const/4 v5, -0x1

    if-ge v4, v3, :cond_1

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v6

    check-cast v6, Llyiahf/vczjk/hr0;

    iget-object v6, v6, Llyiahf/vczjk/hr0;->OooO0O0:Llyiahf/vczjk/sg5;

    if-ne p1, v6, :cond_0

    goto :goto_1

    :cond_0
    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    :cond_1
    move v4, v5

    :goto_1
    if-ne v4, v5, :cond_2

    return-void

    :cond_2
    add-int/lit8 v4, v4, 0x1

    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v3

    if-ge v4, v3, :cond_3

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/hr0;

    :cond_3
    new-instance v1, Llyiahf/vczjk/gr0;

    invoke-direct {v1, p0, v2, p2, p1}, Llyiahf/vczjk/gr0;-><init>(Llyiahf/vczjk/tg7;Llyiahf/vczjk/hr0;Llyiahf/vczjk/dh5;Llyiahf/vczjk/sg5;)V

    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    move-result-wide v2

    const-wide/16 v4, 0xc8

    add-long/2addr v2, v4

    iget-object p2, v0, Llyiahf/vczjk/ir0;->OooOOoo:Landroid/os/Handler;

    invoke-virtual {p2, v1, p1, v2, v3}, Landroid/os/Handler;->postAtTime(Ljava/lang/Runnable;Ljava/lang/Object;J)Z

    return-void
.end method

.method public OooOOOO(Landroid/view/View;Llyiahf/vczjk/ioa;Llyiahf/vczjk/cja;)Llyiahf/vczjk/ioa;
    .locals 7

    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/dockedtoolbar/DockedToolbarLayout;

    iget-object v1, v0, Lcom/google/android/material/dockedtoolbar/DockedToolbarLayout;->OooOOO0:Ljava/lang/Boolean;

    if-eqz v1, :cond_0

    iget-object v2, v0, Lcom/google/android/material/dockedtoolbar/DockedToolbarLayout;->OooOOO:Ljava/lang/Boolean;

    if-eqz v2, :cond_0

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    if-nez v1, :cond_0

    iget-object v1, v0, Lcom/google/android/material/dockedtoolbar/DockedToolbarLayout;->OooOOO:Ljava/lang/Boolean;

    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v1

    if-nez v1, :cond_0

    return-object p2

    :cond_0
    iget-object v1, p2, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    const/16 v2, 0x28f

    invoke-virtual {v1, v2}, Llyiahf/vczjk/foa;->OooO0oO(I)Llyiahf/vczjk/x04;

    move-result-object v1

    iget v2, v1, Llyiahf/vczjk/x04;->OooO0Oo:I

    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v3

    const/16 v4, 0x30

    invoke-static {v0, v3, v4}, Lcom/google/android/material/dockedtoolbar/DockedToolbarLayout;->OooO00o(Lcom/google/android/material/dockedtoolbar/DockedToolbarLayout;Landroid/view/ViewGroup$LayoutParams;I)Z

    move-result v4

    const/4 v5, 0x0

    iget v1, v1, Llyiahf/vczjk/x04;->OooO0O0:I

    if-eqz v4, :cond_1

    iget-object v4, v0, Lcom/google/android/material/dockedtoolbar/DockedToolbarLayout;->OooOOO0:Ljava/lang/Boolean;

    if-nez v4, :cond_1

    invoke-virtual {v0}, Landroid/view/View;->getFitsSystemWindows()Z

    move-result v4

    if-eqz v4, :cond_1

    move v4, v1

    goto :goto_0

    :cond_1
    move v4, v5

    :goto_0
    const/16 v6, 0x50

    invoke-static {v0, v3, v6}, Lcom/google/android/material/dockedtoolbar/DockedToolbarLayout;->OooO00o(Lcom/google/android/material/dockedtoolbar/DockedToolbarLayout;Landroid/view/ViewGroup$LayoutParams;I)Z

    move-result v3

    if-eqz v3, :cond_2

    iget-object v3, v0, Lcom/google/android/material/dockedtoolbar/DockedToolbarLayout;->OooOOO:Ljava/lang/Boolean;

    if-nez v3, :cond_2

    invoke-virtual {v0}, Landroid/view/View;->getFitsSystemWindows()Z

    move-result v3

    if-eqz v3, :cond_2

    move v3, v2

    goto :goto_1

    :cond_2
    move v3, v5

    :goto_1
    iget-object v6, v0, Lcom/google/android/material/dockedtoolbar/DockedToolbarLayout;->OooOOO:Ljava/lang/Boolean;

    if-eqz v6, :cond_4

    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v3

    if-eqz v3, :cond_3

    goto :goto_2

    :cond_3
    move v2, v5

    :goto_2
    move v3, v2

    :cond_4
    iget-object v0, v0, Lcom/google/android/material/dockedtoolbar/DockedToolbarLayout;->OooOOO0:Ljava/lang/Boolean;

    if-eqz v0, :cond_6

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_5

    move v5, v1

    :cond_5
    move v4, v5

    :cond_6
    iget v0, p3, Llyiahf/vczjk/cja;->OooO0O0:I

    add-int/2addr v0, v4

    iput v0, p3, Llyiahf/vczjk/cja;->OooO0O0:I

    iget v1, p3, Llyiahf/vczjk/cja;->OooO0Oo:I

    add-int/2addr v1, v3

    iput v1, p3, Llyiahf/vczjk/cja;->OooO0Oo:I

    iget v2, p3, Llyiahf/vczjk/cja;->OooO00o:I

    iget p3, p3, Llyiahf/vczjk/cja;->OooO0OO:I

    invoke-virtual {p1, v2, v0, p3, v1}, Landroid/view/View;->setPaddingRelative(IIII)V

    return-object p2
.end method

.method public OooOOOo(Llyiahf/vczjk/mp4;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public OooOOo(Llyiahf/vczjk/hy0;Llyiahf/vczjk/yi5;)Llyiahf/vczjk/oO0OOo0o;
    .locals 2

    const-string v0, "classId"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "metadataVersion"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p2, p1, Llyiahf/vczjk/hy0;->OooO0O0:Llyiahf/vczjk/hc3;

    iget-object p2, p2, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    iget-object p2, p2, Llyiahf/vczjk/ic3;->OooO00o:Ljava/lang/String;

    const/16 v0, 0x24

    const/16 v1, 0x2e

    invoke-static {p2, v1, v0}, Llyiahf/vczjk/g79;->OooOooo(Ljava/lang/String;CC)Ljava/lang/String;

    move-result-object p2

    iget-object p1, p1, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    iget-object v0, p1, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0OO()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    :goto_0
    iget-object p1, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast p1, Ljava/lang/ClassLoader;

    invoke-static {p1, p2}, Llyiahf/vczjk/tn6;->OooOo0O(Ljava/lang/ClassLoader;Ljava/lang/String;)Ljava/lang/Class;

    move-result-object p1

    if-eqz p1, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/eo6;->OooO0oo(Ljava/lang/Class;)Llyiahf/vczjk/tm7;

    move-result-object p1

    if-eqz p1, :cond_1

    new-instance p2, Llyiahf/vczjk/oO0OOo0o;

    const/16 v0, 0x17

    invoke-direct {p2, p1, v0}, Llyiahf/vczjk/oO0OOo0o;-><init>(Ljava/lang/Object;I)V

    return-object p2

    :cond_1
    const/4 p1, 0x0

    return-object p1
.end method

.method public OooOOo0(Ljava/util/HashMap;)V
    .locals 5

    invoke-virtual {p1}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/Set;->isEmpty()Z

    move-result v1

    if-eqz v1, :cond_0

    return-void

    :cond_0
    invoke-virtual {p1}, Ljava/util/HashMap;->size()I

    move-result v1

    const/16 v2, 0x3e7

    if-le v1, v2, :cond_1

    new-instance v0, Llyiahf/vczjk/sg7;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Llyiahf/vczjk/sg7;-><init>(Llyiahf/vczjk/tg7;I)V

    invoke-static {p1, v0}, Llyiahf/vczjk/xr6;->OooOOOO(Ljava/util/HashMap;Llyiahf/vczjk/oe3;)V

    return-void

    :cond_1
    const-string v1, "SELECT `tag`,`work_spec_id` FROM `WorkTag` WHERE `work_spec_id` IN ("

    invoke-static {v1}, Llyiahf/vczjk/ii5;->OooOOOO(Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v1

    invoke-interface {v0}, Ljava/util/Set;->size()I

    move-result v2

    invoke-static {v2, v1}, Llyiahf/vczjk/xt6;->OooOo0O(ILjava/lang/StringBuilder;)V

    const-string v3, ")"

    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-static {v2, v1}, Llyiahf/vczjk/xu7;->OooOOOO(ILjava/lang/String;)Llyiahf/vczjk/xu7;

    move-result-object v1

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    const/4 v2, 0x1

    move v3, v2

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_2

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    check-cast v4, Ljava/lang/String;

    invoke-virtual {v1, v3, v4}, Llyiahf/vczjk/xu7;->OooOOO0(ILjava/lang/String;)V

    add-int/2addr v3, v2

    goto :goto_0

    :cond_2
    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroidx/work/impl/WorkDatabase_Impl;

    const/4 v2, 0x0

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/u34;->OoooO0O(Llyiahf/vczjk/ru7;Llyiahf/vczjk/ia9;Z)Landroid/database/Cursor;

    move-result-object v0

    :try_start_0
    const-string v1, "work_spec_id"

    invoke-static {v0, v1}, Llyiahf/vczjk/cp7;->OooOo0O(Landroid/database/Cursor;Ljava/lang/String;)I

    move-result v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    const/4 v3, -0x1

    if-ne v1, v3, :cond_3

    invoke-interface {v0}, Landroid/database/Cursor;->close()V

    return-void

    :cond_3
    :goto_1
    :try_start_1
    invoke-interface {v0}, Landroid/database/Cursor;->moveToNext()Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-interface {v0, v1}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {p1, v3}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Ljava/util/ArrayList;

    if-eqz v3, :cond_3

    invoke-interface {v0, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    :cond_4
    invoke-interface {v0}, Landroid/database/Cursor;->close()V

    return-void

    :goto_2
    invoke-interface {v0}, Landroid/database/Cursor;->close()V

    throw p1
.end method

.method public OooOOoo(Llyiahf/vczjk/hw4;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public OooOo()V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroidx/core/widget/NestedScrollView;

    iget-object v0, v0, Landroidx/core/widget/NestedScrollView;->OooOOOo:Landroid/widget/OverScroller;

    invoke-virtual {v0}, Landroid/widget/OverScroller;->abortAnimation()V

    return-void
.end method

.method public OooOo0(Llyiahf/vczjk/tca;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public OooOo00(Llyiahf/vczjk/o0OoOoOo;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public OooOo0O(Llyiahf/vczjk/sg5;Landroid/view/MenuItem;)Z
    .locals 0

    iget-object p1, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/ld9;

    iget-object p1, p1, Llyiahf/vczjk/ld9;->OooOOo0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/b07;

    if-eqz p1, :cond_0

    invoke-interface {p1, p2}, Llyiahf/vczjk/b07;->onMenuItemClick(Landroid/view/MenuItem;)Z

    move-result p1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public OooOo0o()F
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroidx/core/widget/NestedScrollView;

    invoke-virtual {v0}, Landroidx/core/widget/NestedScrollView;->getVerticalScrollFactorCompat()F

    move-result v0

    neg-float v0, v0

    return v0
.end method

.method public OooOoO(Llyiahf/vczjk/sg5;)V
    .locals 0

    return-void
.end method

.method public OooOoO0(Llyiahf/vczjk/hb7;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/tg7;->OooO0o(Llyiahf/vczjk/rf3;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public OooOoOO(Llyiahf/vczjk/gf4;)Llyiahf/vczjk/dha;
    .locals 2

    const-string v0, "modelClass"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {p1}, Llyiahf/vczjk/gf4;->OooO00o()Ljava/lang/String;

    move-result-object v0

    if-eqz v0, :cond_0

    const-string v1, "androidx.lifecycle.ViewModelProvider.DefaultKey:"

    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/pb7;

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/pb7;->OooOo0O(Llyiahf/vczjk/gf4;Ljava/lang/String;)Llyiahf/vczjk/dha;

    move-result-object p1

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Local and anonymous classes can not be ViewModels"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public OooOoo(Landroidx/recyclerview/widget/o000oOoO;Llyiahf/vczjk/yu2;Llyiahf/vczjk/yu2;)V
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroidx/recyclerview/widget/RecyclerView;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v1, 0x0

    invoke-virtual {p1, v1}, Landroidx/recyclerview/widget/o000oOoO;->OooOOO(Z)V

    iget-object v1, v0, Landroidx/recyclerview/widget/RecyclerView;->OoooOo0:Llyiahf/vczjk/lk7;

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/t22;

    if-eqz p2, :cond_0

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v4, p2, Llyiahf/vczjk/yu2;->OooOOO0:I

    iget v6, p3, Llyiahf/vczjk/yu2;->OooOOO0:I

    if-ne v4, v6, :cond_1

    iget v1, p2, Llyiahf/vczjk/yu2;->OooOOO:I

    iget v3, p3, Llyiahf/vczjk/yu2;->OooOOO:I

    if-eq v1, v3, :cond_0

    goto :goto_0

    :cond_0
    move-object v3, p1

    goto :goto_1

    :cond_1
    :goto_0
    iget v5, p2, Llyiahf/vczjk/yu2;->OooOOO:I

    iget v7, p3, Llyiahf/vczjk/yu2;->OooOOO:I

    move-object v3, p1

    invoke-virtual/range {v2 .. v7}, Llyiahf/vczjk/t22;->OooO0oO(Landroidx/recyclerview/widget/o000oOoO;IIII)Z

    move-result p1

    goto :goto_2

    :goto_1
    invoke-virtual {v2, v3}, Llyiahf/vczjk/t22;->OooOO0o(Landroidx/recyclerview/widget/o000oOoO;)V

    iget-object p1, v3, Landroidx/recyclerview/widget/o000oOoO;->OooOOO0:Landroid/view/View;

    const/4 p2, 0x0

    invoke-virtual {p1, p2}, Landroid/view/View;->setAlpha(F)V

    iget-object p1, v2, Llyiahf/vczjk/t22;->OooO:Ljava/util/ArrayList;

    invoke-virtual {p1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    const/4 p1, 0x1

    :goto_2
    if-eqz p1, :cond_2

    invoke-virtual {v0}, Landroidx/recyclerview/widget/RecyclerView;->OoooOoO()V

    :cond_2
    return-void
.end method

.method public OooOoo0()Llyiahf/vczjk/p29;
    .locals 3

    invoke-static {}, Llyiahf/vczjk/rl2;->OooO00o()Llyiahf/vczjk/rl2;

    move-result-object v0

    invoke-virtual {v0}, Llyiahf/vczjk/rl2;->OooO0OO()I

    move-result v1

    const/4 v2, 0x1

    if-ne v1, v2, :cond_0

    new-instance v0, Llyiahf/vczjk/xv3;

    invoke-direct {v0, v2}, Llyiahf/vczjk/xv3;-><init>(Z)V

    return-object v0

    :cond_0
    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-static {v1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/j22;

    invoke-direct {v2, v1, p0}, Llyiahf/vczjk/j22;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/tg7;)V

    invoke-virtual {v0, v2}, Llyiahf/vczjk/rl2;->OooO0oo(Llyiahf/vczjk/pl2;)V

    return-object v1
.end method

.method public OooOooO()Landroid/view/ViewGroup$LayoutParams;
    .locals 2

    new-instance v0, Landroid/view/ViewGroup$LayoutParams;

    const/4 v1, -0x2

    invoke-direct {v0, v1, v1}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    return-object v0
.end method

.method public OooOooo(Llyiahf/vczjk/wn0;Ljava/lang/Throwable;)V
    .locals 1

    const-string v0, "call"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/yp0;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    return-void
.end method

.method public Oooo000(Landroidx/recyclerview/widget/o000oOoO;Llyiahf/vczjk/yu2;Llyiahf/vczjk/yu2;)V
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Landroidx/recyclerview/widget/RecyclerView;

    iget-object v1, v0, Landroidx/recyclerview/widget/RecyclerView;->OooOOOO:Landroidx/recyclerview/widget/OooOo;

    invoke-virtual {v1, p1}, Landroidx/recyclerview/widget/OooOo;->OooOOO0(Landroidx/recyclerview/widget/o000oOoO;)V

    invoke-virtual {v0, p1}, Landroidx/recyclerview/widget/RecyclerView;->OooOO0(Landroidx/recyclerview/widget/o000oOoO;)V

    const/4 v1, 0x0

    invoke-virtual {p1, v1}, Landroidx/recyclerview/widget/o000oOoO;->OooOOO(Z)V

    iget-object v1, v0, Landroidx/recyclerview/widget/RecyclerView;->OoooOo0:Llyiahf/vczjk/lk7;

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/t22;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget v4, p2, Llyiahf/vczjk/yu2;->OooOOO0:I

    iget v5, p2, Llyiahf/vczjk/yu2;->OooOOO:I

    iget-object p2, p1, Landroidx/recyclerview/widget/o000oOoO;->OooOOO0:Landroid/view/View;

    if-nez p3, :cond_0

    invoke-virtual {p2}, Landroid/view/View;->getLeft()I

    move-result v1

    :goto_0
    move v6, v1

    goto :goto_1

    :cond_0
    iget v1, p3, Llyiahf/vczjk/yu2;->OooOOO0:I

    goto :goto_0

    :goto_1
    if-nez p3, :cond_1

    invoke-virtual {p2}, Landroid/view/View;->getTop()I

    move-result p3

    :goto_2
    move v7, p3

    goto :goto_3

    :cond_1
    iget p3, p3, Llyiahf/vczjk/yu2;->OooOOO:I

    goto :goto_2

    :goto_3
    invoke-virtual {p1}, Landroidx/recyclerview/widget/o000oOoO;->OooO0oo()Z

    move-result p3

    if-nez p3, :cond_2

    if-ne v4, v6, :cond_3

    if-eq v5, v7, :cond_2

    goto :goto_4

    :cond_2
    move-object v3, p1

    goto :goto_5

    :cond_3
    :goto_4
    invoke-virtual {p2}, Landroid/view/View;->getWidth()I

    move-result p3

    add-int/2addr p3, v6

    invoke-virtual {p2}, Landroid/view/View;->getHeight()I

    move-result v1

    add-int/2addr v1, v7

    invoke-virtual {p2, v6, v7, p3, v1}, Landroid/view/View;->layout(IIII)V

    move-object v3, p1

    invoke-virtual/range {v2 .. v7}, Llyiahf/vczjk/t22;->OooO0oO(Landroidx/recyclerview/widget/o000oOoO;IIII)Z

    move-result p1

    goto :goto_6

    :goto_5
    invoke-virtual {v2, v3}, Llyiahf/vczjk/t22;->OooOO0o(Landroidx/recyclerview/widget/o000oOoO;)V

    iget-object p1, v2, Llyiahf/vczjk/t22;->OooO0oo:Ljava/util/ArrayList;

    invoke-virtual {p1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    const/4 p1, 0x1

    :goto_6
    if-eqz p1, :cond_4

    invoke-virtual {v0}, Landroidx/recyclerview/widget/RecyclerView;->OoooOoO()V

    :cond_4
    return-void
.end method

.method public Oooo00O(Llyiahf/vczjk/va7;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/tg7;->OooO0o(Llyiahf/vczjk/rf3;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public Oooo00o(Ljava/lang/Class;Llyiahf/vczjk/cy8;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Ljava/util/HashMap;

    invoke-virtual {v0, p1, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

.method public Oooo0OO(Llyiahf/vczjk/ih6;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public Oooo0o()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;

    iget v0, v0, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;->OooooO0:I

    return v0
.end method

.method public Oooo0oO(Landroid/view/View;Llyiahf/vczjk/ioa;)Llyiahf/vczjk/ioa;
    .locals 16

    move-object/from16 v1, p0

    move-object/from16 v2, p2

    iget v0, v1, Llyiahf/vczjk/tg7;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, v1, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/appbar/CollapsingToolbarLayout;

    invoke-virtual {v0}, Landroid/view/View;->getFitsSystemWindows()Z

    move-result v3

    if-eqz v3, :cond_0

    move-object v3, v2

    goto :goto_0

    :cond_0
    const/4 v3, 0x0

    :goto_0
    iget-object v4, v0, Lcom/google/android/material/appbar/CollapsingToolbarLayout;->OoooO00:Llyiahf/vczjk/ioa;

    invoke-static {v4, v3}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_1

    iput-object v3, v0, Lcom/google/android/material/appbar/CollapsingToolbarLayout;->OoooO00:Llyiahf/vczjk/ioa;

    invoke-virtual {v0}, Landroid/view/View;->requestLayout()V

    :cond_1
    iget-object v0, v2, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    invoke-virtual {v0}, Llyiahf/vczjk/foa;->OooO0OO()Llyiahf/vczjk/ioa;

    move-result-object v0

    return-object v0

    :pswitch_0
    invoke-virtual {v2}, Llyiahf/vczjk/ioa;->OooO0Oo()I

    move-result v3

    iget-object v0, v1, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    move-object v4, v0

    check-cast v4, Llyiahf/vczjk/jr;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v2}, Llyiahf/vczjk/ioa;->OooO0Oo()I

    move-result v5

    iget-object v0, v4, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    const/4 v6, 0x0

    const/16 v7, 0x8

    if-eqz v0, :cond_13

    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v0

    instance-of v0, v0, Landroid/view/ViewGroup$MarginLayoutParams;

    if-eqz v0, :cond_13

    iget-object v0, v4, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v0

    move-object v8, v0

    check-cast v8, Landroid/view/ViewGroup$MarginLayoutParams;

    iget-object v0, v4, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v0}, Landroid/view/View;->isShown()Z

    move-result v0

    const/4 v9, 0x1

    if-eqz v0, :cond_11

    iget-object v0, v4, Llyiahf/vczjk/jr;->o00Ooo:Landroid/graphics/Rect;

    if-nez v0, :cond_2

    new-instance v0, Landroid/graphics/Rect;

    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    iput-object v0, v4, Llyiahf/vczjk/jr;->o00Ooo:Landroid/graphics/Rect;

    new-instance v0, Landroid/graphics/Rect;

    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    iput-object v0, v4, Llyiahf/vczjk/jr;->o00o0O:Landroid/graphics/Rect;

    :cond_2
    iget-object v10, v4, Llyiahf/vczjk/jr;->o00Ooo:Landroid/graphics/Rect;

    iget-object v0, v4, Llyiahf/vczjk/jr;->o00o0O:Landroid/graphics/Rect;

    invoke-virtual {v2}, Llyiahf/vczjk/ioa;->OooO0O0()I

    move-result v11

    invoke-virtual {v2}, Llyiahf/vczjk/ioa;->OooO0Oo()I

    move-result v12

    invoke-virtual {v2}, Llyiahf/vczjk/ioa;->OooO0OO()I

    move-result v13

    invoke-virtual {v2}, Llyiahf/vczjk/ioa;->OooO00o()I

    move-result v14

    invoke-virtual {v10, v11, v12, v13, v14}, Landroid/graphics/Rect;->set(IIII)V

    iget-object v11, v4, Llyiahf/vczjk/jr;->Oooo0o:Landroid/view/ViewGroup;

    const-class v12, Landroid/graphics/Rect;

    sget v13, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v14, 0x1d

    if-lt v13, v14, :cond_3

    sget-boolean v12, Llyiahf/vczjk/eja;->OooO00o:Z

    invoke-static {v11, v10, v0}, Llyiahf/vczjk/aja;->OooO00o(Landroid/view/View;Landroid/graphics/Rect;Landroid/graphics/Rect;)V

    goto :goto_2

    :cond_3
    sget-boolean v13, Llyiahf/vczjk/eja;->OooO00o:Z

    const-string v14, "ViewUtils"

    if-nez v13, :cond_4

    sput-boolean v9, Llyiahf/vczjk/eja;->OooO00o:Z

    :try_start_0
    const-class v13, Landroid/view/View;

    const-string v15, "computeFitSystemWindows"

    filled-new-array {v12, v12}, [Ljava/lang/Class;

    move-result-object v12

    invoke-virtual {v13, v15, v12}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    move-result-object v12

    sput-object v12, Llyiahf/vczjk/eja;->OooO0O0:Ljava/lang/reflect/Method;

    invoke-virtual {v12}, Ljava/lang/reflect/AccessibleObject;->isAccessible()Z

    move-result v12

    if-nez v12, :cond_4

    sget-object v12, Llyiahf/vczjk/eja;->OooO0O0:Ljava/lang/reflect/Method;

    invoke-virtual {v12, v9}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    :catch_0
    const-string v12, "Could not find method computeFitSystemWindows. Oh well."

    invoke-static {v14, v12}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    :cond_4
    :goto_1
    sget-object v12, Llyiahf/vczjk/eja;->OooO0O0:Ljava/lang/reflect/Method;

    if-eqz v12, :cond_5

    :try_start_1
    filled-new-array {v10, v0}, [Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {v12, v11, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_2

    :catch_1
    move-exception v0

    const-string v11, "Could not invoke computeFitSystemWindows"

    invoke-static {v14, v11, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    :cond_5
    :goto_2
    iget v0, v10, Landroid/graphics/Rect;->top:I

    iget v11, v10, Landroid/graphics/Rect;->left:I

    iget v10, v10, Landroid/graphics/Rect;->right:I

    iget-object v12, v4, Llyiahf/vczjk/jr;->Oooo0o:Landroid/view/ViewGroup;

    sget-object v13, Llyiahf/vczjk/xfa;->OooO00o:Ljava/util/WeakHashMap;

    invoke-static {v12}, Llyiahf/vczjk/pfa;->OooO00o(Landroid/view/View;)Llyiahf/vczjk/ioa;

    move-result-object v12

    if-nez v12, :cond_6

    move v13, v6

    goto :goto_3

    :cond_6
    invoke-virtual {v12}, Llyiahf/vczjk/ioa;->OooO0O0()I

    move-result v13

    :goto_3
    if-nez v12, :cond_7

    move v12, v6

    goto :goto_4

    :cond_7
    invoke-virtual {v12}, Llyiahf/vczjk/ioa;->OooO0OO()I

    move-result v12

    :goto_4
    iget v14, v8, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    if-ne v14, v0, :cond_9

    iget v14, v8, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    if-ne v14, v11, :cond_9

    iget v14, v8, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    if-eq v14, v10, :cond_8

    goto :goto_5

    :cond_8
    move v10, v6

    goto :goto_6

    :cond_9
    :goto_5
    iput v0, v8, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    iput v11, v8, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    iput v10, v8, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    move v10, v9

    :goto_6
    iget-object v11, v4, Llyiahf/vczjk/jr;->OooOo0o:Landroid/content/Context;

    if-lez v0, :cond_a

    iget-object v0, v4, Llyiahf/vczjk/jr;->Oooo0oo:Landroid/view/View;

    if-nez v0, :cond_a

    new-instance v0, Landroid/view/View;

    invoke-direct {v0, v11}, Landroid/view/View;-><init>(Landroid/content/Context;)V

    iput-object v0, v4, Llyiahf/vczjk/jr;->Oooo0oo:Landroid/view/View;

    invoke-virtual {v0, v7}, Landroid/view/View;->setVisibility(I)V

    new-instance v0, Landroid/widget/FrameLayout$LayoutParams;

    iget v14, v8, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    const/16 v15, 0x33

    const/4 v7, -0x1

    invoke-direct {v0, v7, v14, v15}, Landroid/widget/FrameLayout$LayoutParams;-><init>(III)V

    iput v13, v0, Landroid/widget/FrameLayout$LayoutParams;->leftMargin:I

    iput v12, v0, Landroid/widget/FrameLayout$LayoutParams;->rightMargin:I

    iget-object v12, v4, Llyiahf/vczjk/jr;->Oooo0o:Landroid/view/ViewGroup;

    iget-object v13, v4, Llyiahf/vczjk/jr;->Oooo0oo:Landroid/view/View;

    invoke-virtual {v12, v13, v7, v0}, Landroid/view/ViewGroup;->addView(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)V

    goto :goto_7

    :cond_a
    iget-object v0, v4, Llyiahf/vczjk/jr;->Oooo0oo:Landroid/view/View;

    if-eqz v0, :cond_c

    invoke-virtual {v0}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v0

    check-cast v0, Landroid/view/ViewGroup$MarginLayoutParams;

    iget v7, v0, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    iget v14, v8, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    if-ne v7, v14, :cond_b

    iget v7, v0, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    if-ne v7, v13, :cond_b

    iget v7, v0, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    if-eq v7, v12, :cond_c

    :cond_b
    iput v14, v0, Landroid/view/ViewGroup$MarginLayoutParams;->height:I

    iput v13, v0, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    iput v12, v0, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    iget-object v7, v4, Llyiahf/vczjk/jr;->Oooo0oo:Landroid/view/View;

    invoke-virtual {v7, v0}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    :cond_c
    :goto_7
    iget-object v0, v4, Llyiahf/vczjk/jr;->Oooo0oo:Landroid/view/View;

    if-eqz v0, :cond_d

    goto :goto_8

    :cond_d
    move v9, v6

    :goto_8
    if-eqz v9, :cond_f

    invoke-virtual {v0}, Landroid/view/View;->getVisibility()I

    move-result v0

    if-eqz v0, :cond_f

    iget-object v0, v4, Llyiahf/vczjk/jr;->Oooo0oo:Landroid/view/View;

    invoke-virtual {v0}, Landroid/view/View;->getWindowSystemUiVisibility()I

    move-result v7

    and-int/lit16 v7, v7, 0x2000

    if-eqz v7, :cond_e

    sget v7, Landroidx/appcompat/R$color;->abc_decor_view_status_guard_light:I

    invoke-virtual {v11, v7}, Landroid/content/Context;->getColor(I)I

    move-result v7

    goto :goto_9

    :cond_e
    sget v7, Landroidx/appcompat/R$color;->abc_decor_view_status_guard:I

    invoke-virtual {v11, v7}, Landroid/content/Context;->getColor(I)I

    move-result v7

    :goto_9
    invoke-virtual {v0, v7}, Landroid/view/View;->setBackgroundColor(I)V

    :cond_f
    iget-boolean v0, v4, Llyiahf/vczjk/jr;->OoooO:Z

    if-nez v0, :cond_10

    if-eqz v9, :cond_10

    move v5, v6

    :cond_10
    move v0, v9

    move v9, v10

    goto :goto_a

    :cond_11
    iget v0, v8, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    if-eqz v0, :cond_12

    iput v6, v8, Landroid/view/ViewGroup$MarginLayoutParams;->topMargin:I

    move v0, v6

    goto :goto_a

    :cond_12
    move v0, v6

    move v9, v0

    :goto_a
    if-eqz v9, :cond_14

    iget-object v7, v4, Llyiahf/vczjk/jr;->Oooo00o:Landroidx/appcompat/widget/ActionBarContextView;

    invoke-virtual {v7, v8}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    goto :goto_b

    :cond_13
    move v0, v6

    :cond_14
    :goto_b
    iget-object v4, v4, Llyiahf/vczjk/jr;->Oooo0oo:Landroid/view/View;

    if-eqz v4, :cond_16

    if-eqz v0, :cond_15

    goto :goto_c

    :cond_15
    const/16 v6, 0x8

    :goto_c
    invoke-virtual {v4, v6}, Landroid/view/View;->setVisibility(I)V

    :cond_16
    if-eq v3, v5, :cond_17

    invoke-virtual {v2}, Llyiahf/vczjk/ioa;->OooO0O0()I

    move-result v0

    invoke-virtual {v2}, Llyiahf/vczjk/ioa;->OooO0OO()I

    move-result v3

    invoke-virtual {v2}, Llyiahf/vczjk/ioa;->OooO00o()I

    move-result v4

    invoke-virtual {v2, v0, v5, v3, v4}, Llyiahf/vczjk/ioa;->OooO0o(IIII)Llyiahf/vczjk/ioa;

    move-result-object v0

    :goto_d
    move-object/from16 v2, p1

    goto :goto_e

    :cond_17
    move-object v0, v2

    goto :goto_d

    :goto_e
    invoke-static {v2, v0}, Llyiahf/vczjk/xfa;->OooOO0(Landroid/view/View;Llyiahf/vczjk/ioa;)Llyiahf/vczjk/ioa;

    move-result-object v0

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method

.method public Oooo0oo(Llyiahf/vczjk/wn0;Llyiahf/vczjk/hs7;)V
    .locals 1

    const-string v0, "call"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/yp0;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/yp0;->resumeWith(Ljava/lang/Object;)V

    return-void
.end method

.method public OoooO(Ljava/lang/Object;Llyiahf/vczjk/dm5;)Ljava/lang/Object;
    .locals 0

    const/4 p1, 0x0

    return-object p1
.end method

.method public OoooO00(Llyiahf/vczjk/ua7;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p2, Llyiahf/vczjk/z8a;

    const-string p2, "descriptor"

    invoke-static {p1, p2}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p2, p1, Llyiahf/vczjk/ua7;->Oooo0:Llyiahf/vczjk/mp4;

    const/4 v0, 0x0

    const/4 v1, 0x1

    if-eqz p2, :cond_0

    move p2, v1

    goto :goto_0

    :cond_0
    move p2, v0

    :goto_0
    iget-object v2, p1, Llyiahf/vczjk/ua7;->Oooo0O0:Llyiahf/vczjk/mp4;

    if-eqz v2, :cond_1

    move v0, v1

    :cond_1
    add-int/2addr p2, v0

    iget-boolean v0, p1, Llyiahf/vczjk/ua7;->OooOo0:Z

    const/4 v2, 0x2

    iget-object v3, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/yf4;

    if-eqz v0, :cond_4

    if-eqz p2, :cond_3

    if-eq p2, v1, :cond_2

    if-ne p2, v2, :cond_5

    new-instance p2, Llyiahf/vczjk/qg4;

    invoke-direct {p2, v3, p1}, Llyiahf/vczjk/qg4;-><init>(Llyiahf/vczjk/yf4;Llyiahf/vczjk/ua7;)V

    return-object p2

    :cond_2
    new-instance p2, Llyiahf/vczjk/og4;

    invoke-direct {p2, v3, p1}, Llyiahf/vczjk/og4;-><init>(Llyiahf/vczjk/yf4;Llyiahf/vczjk/ua7;)V

    return-object p2

    :cond_3
    new-instance p2, Llyiahf/vczjk/kg4;

    invoke-direct {p2, v3, p1}, Llyiahf/vczjk/kg4;-><init>(Llyiahf/vczjk/yf4;Llyiahf/vczjk/ua7;)V

    return-object p2

    :cond_4
    if-eqz p2, :cond_7

    if-eq p2, v1, :cond_6

    if-ne p2, v2, :cond_5

    new-instance p2, Llyiahf/vczjk/sh4;

    invoke-direct {p2, v3, p1}, Llyiahf/vczjk/sh4;-><init>(Llyiahf/vczjk/yf4;Llyiahf/vczjk/ua7;)V

    return-object p2

    :cond_5
    new-instance p2, Llyiahf/vczjk/es1;

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Unsupported property: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-direct {p2, p1}, Llyiahf/vczjk/es1;-><init>(Ljava/lang/String;)V

    throw p2

    :cond_6
    new-instance p2, Llyiahf/vczjk/ph4;

    invoke-direct {p2, v3, p1}, Llyiahf/vczjk/ph4;-><init>(Llyiahf/vczjk/yf4;Llyiahf/vczjk/ua7;)V

    return-object p2

    :cond_7
    new-instance p2, Llyiahf/vczjk/kh4;

    invoke-direct {p2, v3, p1}, Llyiahf/vczjk/kh4;-><init>(Llyiahf/vczjk/yf4;Llyiahf/vczjk/ua7;)V

    return-object p2
.end method

.method public getHeight()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;

    invoke-virtual {v0}, Landroid/view/View;->getMeasuredHeight()I

    move-result v0

    return v0
.end method

.method public getWidth()I
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;

    invoke-virtual {v0}, Landroid/view/View;->getMeasuredWidth()I

    move-result v1

    invoke-virtual {v0}, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;->getCollapsedPadding()I

    move-result v2

    mul-int/lit8 v2, v2, 0x2

    sub-int/2addr v1, v2

    iget v2, v0, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;->OooooO0:I

    add-int/2addr v1, v2

    iget v0, v0, Lcom/google/android/material/floatingactionbutton/ExtendedFloatingActionButton;->OooooOO:I

    add-int/2addr v1, v0

    return v1
.end method

.method public test(Ljava/lang/Object;)Z
    .locals 4

    check-cast p1, Llyiahf/vczjk/wu;

    iget-object v0, p0, Llyiahf/vczjk/tg7;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/t41;

    iget-object v1, v0, Llyiahf/vczjk/t41;->OooO:Landroidx/databinding/ObservableField;

    invoke-virtual {v1}, Landroidx/databinding/ObservableField;->get()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_2

    if-eqz v1, :cond_0

    invoke-virtual {v1}, Ljava/lang/String;->length()I

    move-result v2

    const/4 v3, 0x2

    if-le v2, v3, :cond_0

    iget-object v2, p1, Llyiahf/vczjk/wu;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {v2}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getPkgName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v2, v1}, Ljava/lang/String;->contains(Ljava/lang/CharSequence;)Z

    move-result v2

    if-nez v2, :cond_2

    :cond_0
    iget-object p1, p1, Llyiahf/vczjk/wu;->OooOOO0:Lgithub/tornaco/android/thanos/core/pm/AppInfo;

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/pm/AppInfo;->getAppLabel()Ljava/lang/String;

    move-result-object p1

    iget-object v0, v0, Llyiahf/vczjk/t41;->OooOO0:Llyiahf/vczjk/hu;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1, p1}, Llyiahf/vczjk/hu;->OooO00o(Ljava/lang/String;Ljava/lang/String;)Z

    move-result p1

    if-eqz p1, :cond_1

    goto :goto_0

    :cond_1
    const/4 p1, 0x0

    return p1

    :cond_2
    :goto_0
    const/4 p1, 0x1

    return p1
.end method
