.class public abstract Llyiahf/vczjk/gm8;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO:Ljava/util/ArrayList;

.field public static OooO00o:Landroid/os/IBinder; = null

.field public static OooO0O0:Llyiahf/vczjk/jt3; = null

.field public static OooO0OO:Z = false

.field public static OooO0Oo:Z = false

.field public static final OooO0o:Llyiahf/vczjk/em8;

.field public static OooO0o0:Z = false

.field public static final OooO0oO:Llyiahf/vczjk/dm8;

.field public static final OooO0oo:Ljava/util/ArrayList;

.field public static final OooOO0:Ljava/util/ArrayList;

.field public static final OooOO0O:Landroid/os/Handler;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/em8;

    invoke-direct {v0}, Landroid/os/Binder;-><init>()V

    const-string v1, "moe.shizuku.server.IShizukuApplication"

    invoke-virtual {v0, v0, v1}, Landroid/os/Binder;->attachInterface(Landroid/os/IInterface;Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/gm8;->OooO0o:Llyiahf/vczjk/em8;

    new-instance v0, Llyiahf/vczjk/dm8;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/gm8;->OooO0oO:Llyiahf/vczjk/dm8;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    sput-object v0, Llyiahf/vczjk/gm8;->OooO0oo:Ljava/util/ArrayList;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    sput-object v0, Llyiahf/vczjk/gm8;->OooO:Ljava/util/ArrayList;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    sput-object v0, Llyiahf/vczjk/gm8;->OooOO0:Ljava/util/ArrayList;

    new-instance v0, Landroid/os/Handler;

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v1

    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    sput-object v0, Llyiahf/vczjk/gm8;->OooOO0O:Landroid/os/Handler;

    return-void
.end method

.method public static OooO00o(Ljava/lang/String;Landroid/os/IBinder;)Z
    .locals 3

    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    move-result-object v0

    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    move-result-object v1

    :try_start_0
    const-string v2, "moe.shizuku.server.IShizukuService"

    invoke-virtual {v0, v2}, Landroid/os/Parcel;->writeInterfaceToken(Ljava/lang/String;)V

    sget-object v2, Llyiahf/vczjk/gm8;->OooO0o:Llyiahf/vczjk/em8;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {v0, v2}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    invoke-virtual {v0, p0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    const/16 p0, 0xe

    const/4 v2, 0x0

    invoke-interface {p1, p0, v0, v1, v2}, Landroid/os/IBinder;->transact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z

    move-result p0

    invoke-virtual {v1}, Landroid/os/Parcel;->readException()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {v1}, Landroid/os/Parcel;->recycle()V

    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V

    return p0

    :catchall_0
    move-exception p0

    invoke-virtual {v1}, Landroid/os/Parcel;->recycle()V

    invoke-virtual {v0}, Landroid/os/Parcel;->recycle()V

    throw p0
.end method

.method public static OooO0O0(Ljava/lang/String;Landroid/os/IBinder;)Z
    .locals 3

    new-instance v0, Landroid/os/Bundle;

    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    const-string v1, "shizuku:attach-api-version"

    const/16 v2, 0xd

    invoke-virtual {v0, v1, v2}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    const-string v1, "shizuku:attach-package-name"

    invoke-virtual {v0, v1, p0}, Landroid/os/BaseBundle;->putString(Ljava/lang/String;Ljava/lang/String;)V

    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    move-result-object p0

    invoke-static {}, Landroid/os/Parcel;->obtain()Landroid/os/Parcel;

    move-result-object v1

    :try_start_0
    const-string v2, "moe.shizuku.server.IShizukuService"

    invoke-virtual {p0, v2}, Landroid/os/Parcel;->writeInterfaceToken(Ljava/lang/String;)V

    sget-object v2, Llyiahf/vczjk/gm8;->OooO0o:Llyiahf/vczjk/em8;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-virtual {p0, v2}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    const/4 v2, 0x1

    invoke-virtual {p0, v2}, Landroid/os/Parcel;->writeInt(I)V

    const/4 v2, 0x0

    invoke-virtual {v0, p0, v2}, Landroid/os/Bundle;->writeToParcel(Landroid/os/Parcel;I)V

    const/16 v0, 0x12

    invoke-interface {p1, v0, p0, v1, v2}, Landroid/os/IBinder;->transact(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z

    move-result p1

    invoke-virtual {v1}, Landroid/os/Parcel;->readException()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    invoke-virtual {v1}, Landroid/os/Parcel;->recycle()V

    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    return p1

    :catchall_0
    move-exception p1

    invoke-virtual {v1}, Landroid/os/Parcel;->recycle()V

    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    throw p1
.end method

.method public static OooO0OO()I
    .locals 2

    sget-boolean v0, Llyiahf/vczjk/gm8;->OooO0OO:Z

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    :try_start_0
    invoke-static {}, Llyiahf/vczjk/gm8;->OooO0o0()Llyiahf/vczjk/jt3;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/ht3;

    invoke-virtual {v0}, Llyiahf/vczjk/ht3;->OooO0oO()Z

    move-result v0

    sput-boolean v0, Llyiahf/vczjk/gm8;->OooO0OO:Z
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    if-eqz v0, :cond_1

    :goto_0
    const/4 v0, 0x0

    return v0

    :cond_1
    const/4 v0, -0x1

    return v0

    :catch_0
    move-exception v0

    new-instance v1, Ljava/lang/RuntimeException;

    invoke-direct {v1, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    throw v1
.end method

.method public static OooO0Oo(Ljava/lang/String;Landroid/os/IBinder;)V
    .locals 4

    sget-object v0, Llyiahf/vczjk/gm8;->OooO00o:Landroid/os/IBinder;

    if-ne v0, p1, :cond_0

    goto/16 :goto_5

    :cond_0
    if-nez p1, :cond_3

    const/4 p0, 0x0

    sput-object p0, Llyiahf/vczjk/gm8;->OooO00o:Landroid/os/IBinder;

    sput-object p0, Llyiahf/vczjk/gm8;->OooO0O0:Llyiahf/vczjk/jt3;

    sget-object v1, Llyiahf/vczjk/gm8;->OooO0oo:Ljava/util/ArrayList;

    monitor-enter v1

    :try_start_0
    sget-object p0, Llyiahf/vczjk/gm8;->OooO:Ljava/util/ArrayList;

    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result p1

    if-eqz p1, :cond_2

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/fm8;

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    move-result-object v0

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v2

    if-ne v0, v2, :cond_1

    iget-object p1, p1, Llyiahf/vczjk/fm8;->OooO00o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/tm8;

    iget-object p1, p1, Llyiahf/vczjk/tm8;->OooO00o:Llyiahf/vczjk/vm8;

    invoke-virtual {p1}, Llyiahf/vczjk/vm8;->OooO()V

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :cond_1
    sget-object v0, Llyiahf/vczjk/gm8;->OooOO0O:Landroid/os/Handler;

    iget-object p1, p1, Llyiahf/vczjk/fm8;->OooO00o:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/tm8;

    new-instance v2, Llyiahf/vczjk/xy3;

    const/16 v3, 0x10

    invoke-direct {v2, p1, v3}, Llyiahf/vczjk/xy3;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v0, v2}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    goto :goto_0

    :cond_2
    monitor-exit v1

    return-void

    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0

    :cond_3
    const/4 v1, 0x0

    if-eqz v0, :cond_4

    sget-object v2, Llyiahf/vczjk/gm8;->OooO0oO:Llyiahf/vczjk/dm8;

    invoke-interface {v0, v2, v1}, Landroid/os/IBinder;->unlinkToDeath(Landroid/os/IBinder$DeathRecipient;I)Z

    :cond_4
    sput-object p1, Llyiahf/vczjk/gm8;->OooO00o:Landroid/os/IBinder;

    sget v0, Llyiahf/vczjk/it3;->OooO0o0:I

    const-string v0, "moe.shizuku.server.IShizukuService"

    invoke-interface {p1, v0}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    move-result-object v0

    if-eqz v0, :cond_5

    instance-of v2, v0, Llyiahf/vczjk/jt3;

    if-eqz v2, :cond_5

    check-cast v0, Llyiahf/vczjk/jt3;

    goto :goto_2

    :cond_5
    new-instance v0, Llyiahf/vczjk/ht3;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput-object p1, v0, Llyiahf/vczjk/ht3;->OooO0o0:Landroid/os/IBinder;

    :goto_2
    sput-object v0, Llyiahf/vczjk/gm8;->OooO0O0:Llyiahf/vczjk/jt3;

    :try_start_1
    sget-object p1, Llyiahf/vczjk/gm8;->OooO00o:Landroid/os/IBinder;

    sget-object v0, Llyiahf/vczjk/gm8;->OooO0oO:Llyiahf/vczjk/dm8;

    invoke-interface {p1, v0, v1}, Landroid/os/IBinder;->linkToDeath(Landroid/os/IBinder$DeathRecipient;I)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_3

    :catchall_1
    const-string p1, "ShizukuApplication"

    const-string v0, "attachApplication"

    invoke-static {p1, v0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    :goto_3
    :try_start_2
    sget-object p1, Llyiahf/vczjk/gm8;->OooO00o:Landroid/os/IBinder;

    invoke-static {p0, p1}, Llyiahf/vczjk/gm8;->OooO0O0(Ljava/lang/String;Landroid/os/IBinder;)Z

    move-result p1

    if-nez p1, :cond_6

    sget-object p1, Llyiahf/vczjk/gm8;->OooO00o:Landroid/os/IBinder;

    invoke-static {p0, p1}, Llyiahf/vczjk/gm8;->OooO00o(Ljava/lang/String;Landroid/os/IBinder;)Z

    move-result p0

    if-nez p0, :cond_6

    const/4 p0, 0x1

    sput-boolean p0, Llyiahf/vczjk/gm8;->OooO0o0:Z

    :cond_6
    const-string p0, "ShizukuApplication"

    const-string p1, "attachApplication"

    invoke-static {p0, p1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    goto :goto_4

    :catchall_2
    move-exception p0

    const-string p1, "ShizukuApplication"

    invoke-static {p0}, Landroid/util/Log;->getStackTraceString(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object p0

    invoke-static {p1, p0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    :goto_4
    sget-boolean p0, Llyiahf/vczjk/gm8;->OooO0o0:Z

    if-eqz p0, :cond_7

    invoke-static {}, Llyiahf/vczjk/gm8;->OooO0o()V

    :cond_7
    :goto_5
    return-void
.end method

.method public static OooO0o()V
    .locals 6

    sget-object v0, Llyiahf/vczjk/gm8;->OooO0oo:Ljava/util/ArrayList;

    monitor-enter v0

    :try_start_0
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/fm8;

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    move-result-object v3

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v4

    if-ne v3, v4, :cond_0

    iget-object v2, v2, Llyiahf/vczjk/fm8;->OooO00o:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/sm8;

    invoke-virtual {v2}, Llyiahf/vczjk/sm8;->OooO00o()V

    goto :goto_0

    :catchall_0
    move-exception v1

    goto :goto_1

    :cond_0
    sget-object v3, Llyiahf/vczjk/gm8;->OooOO0O:Landroid/os/Handler;

    iget-object v2, v2, Llyiahf/vczjk/fm8;->OooO00o:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/sm8;

    new-instance v4, Llyiahf/vczjk/xy3;

    const/16 v5, 0xf

    invoke-direct {v4, v2, v5}, Llyiahf/vczjk/xy3;-><init>(Ljava/lang/Object;I)V

    invoke-virtual {v3, v4}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    goto :goto_0

    :cond_1
    monitor-exit v0

    return-void

    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v1
.end method

.method public static OooO0o0()Llyiahf/vczjk/jt3;
    .locals 2

    sget-object v0, Llyiahf/vczjk/gm8;->OooO0O0:Llyiahf/vczjk/jt3;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "binder haven\'t been received"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
