.class public abstract Llyiahf/vczjk/uy8;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Ljava/util/LinkedHashSet;

.field public static final OooO0O0:Llyiahf/vczjk/hy0;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    sget-object v0, Llyiahf/vczjk/dd4;->OooO00o:Llyiahf/vczjk/hc3;

    sget-object v1, Llyiahf/vczjk/dd4;->OooO0oo:Llyiahf/vczjk/hc3;

    sget-object v2, Llyiahf/vczjk/dd4;->OooO:Llyiahf/vczjk/hc3;

    sget-object v3, Llyiahf/vczjk/dd4;->OooO0OO:Llyiahf/vczjk/hc3;

    sget-object v4, Llyiahf/vczjk/dd4;->OooO0Oo:Llyiahf/vczjk/hc3;

    sget-object v5, Llyiahf/vczjk/dd4;->OooO0o:Llyiahf/vczjk/hc3;

    filled-new-array/range {v0 .. v5}, [Llyiahf/vczjk/hc3;

    move-result-object v0

    invoke-static {v0}, Llyiahf/vczjk/e21;->Oooo([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    new-instance v1, Ljava/util/LinkedHashSet;

    invoke-direct {v1}, Ljava/util/LinkedHashSet;-><init>()V

    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_0

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/hc3;

    const-string v3, "topLevelFqName"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v3, Llyiahf/vczjk/hy0;

    invoke-virtual {v2}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v4

    iget-object v2, v2, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v2}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v2

    invoke-direct {v3, v4, v2}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    invoke-interface {v1, v3}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    sput-object v1, Llyiahf/vczjk/uy8;->OooO00o:Ljava/util/LinkedHashSet;

    sget-object v0, Llyiahf/vczjk/dd4;->OooO0oO:Llyiahf/vczjk/hc3;

    const-string v1, "REPEATABLE_ANNOTATION"

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v1, Llyiahf/vczjk/hy0;

    invoke-virtual {v0}, Llyiahf/vczjk/hc3;->OooO0O0()Llyiahf/vczjk/hc3;

    move-result-object v2

    iget-object v0, v0, Llyiahf/vczjk/hc3;->OooO00o:Llyiahf/vczjk/ic3;

    invoke-virtual {v0}, Llyiahf/vczjk/ic3;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v0

    invoke-direct {v1, v2, v0}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    sput-object v1, Llyiahf/vczjk/uy8;->OooO0O0:Llyiahf/vczjk/hy0;

    return-void
.end method
