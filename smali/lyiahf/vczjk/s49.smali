.class public final Llyiahf/vczjk/s49;
.super Llyiahf/vczjk/v49;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# instance fields
.field protected final _ctor:Ljava/lang/reflect/Constructor;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/reflect/Constructor<",
            "*>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/lang/reflect/Constructor;)V
    .locals 3

    invoke-virtual {p1}, Ljava/lang/reflect/Constructor;->getDeclaringClass()Ljava/lang/Class;

    move-result-object v0

    const/4 v1, 0x0

    const/4 v2, -0x1

    invoke-direct {p0, v2, v0, v1}, Llyiahf/vczjk/v49;-><init>(ILjava/lang/Class;Llyiahf/vczjk/ie3;)V

    iput-object p1, p0, Llyiahf/vczjk/s49;->_ctor:Ljava/lang/reflect/Constructor;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Ljava/lang/String;Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 0

    iget-object p2, p0, Llyiahf/vczjk/s49;->_ctor:Ljava/lang/reflect/Constructor;

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-virtual {p2, p1}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
