.class public abstract Llyiahf/vczjk/rn0;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/era;

.field public static final OooO0O0:Llyiahf/vczjk/era;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/tn;->OooOOo:Llyiahf/vczjk/tn;

    sget v1, Llyiahf/vczjk/om0;->OooO00o:I

    new-instance v1, Llyiahf/vczjk/era;

    invoke-direct {v1, v0}, Llyiahf/vczjk/era;-><init>(Llyiahf/vczjk/oe3;)V

    sput-object v1, Llyiahf/vczjk/rn0;->OooO00o:Llyiahf/vczjk/era;

    sget-object v0, Llyiahf/vczjk/tn;->OooOOoo:Llyiahf/vczjk/tn;

    new-instance v1, Llyiahf/vczjk/era;

    invoke-direct {v1, v0}, Llyiahf/vczjk/era;-><init>(Llyiahf/vczjk/oe3;)V

    sput-object v1, Llyiahf/vczjk/rn0;->OooO0O0:Llyiahf/vczjk/era;

    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    return-void
.end method

.method public static final OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/of4;
    .locals 3

    const-string v0, "jClass"

    invoke-static {p0, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    sget-object v0, Llyiahf/vczjk/rn0;->OooO00o:Llyiahf/vczjk/era;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    iget-object v1, v0, Llyiahf/vczjk/era;->OooOOO:Ljava/lang/Object;

    check-cast v1, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v1, p0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    if-nez v2, :cond_1

    iget-object v0, v0, Llyiahf/vczjk/era;->OooOOO0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/oe3;

    invoke-interface {v0, p0}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v2

    invoke-virtual {v1, p0, v2}, Ljava/util/concurrent/ConcurrentHashMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    if-nez p0, :cond_0

    goto :goto_0

    :cond_0
    move-object v2, p0

    :cond_1
    :goto_0
    const-string p0, "null cannot be cast to non-null type kotlin.reflect.jvm.internal.KClassImpl<T of kotlin.reflect.jvm.internal.CachesKt.getOrCreateKotlinClass>"

    invoke-static {v2, p0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v2, Llyiahf/vczjk/of4;

    return-object v2
.end method
