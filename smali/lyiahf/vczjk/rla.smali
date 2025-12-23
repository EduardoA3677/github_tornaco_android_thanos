.class public abstract Llyiahf/vczjk/rla;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Ljava/util/HashSet;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Ljava/util/HashSet;

    sget-object v1, Llyiahf/vczjk/ula;->OooO00o:Llyiahf/vczjk/vla;

    invoke-interface {v1}, Llyiahf/vczjk/vla;->OooO0o0()[Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    sput-object v0, Llyiahf/vczjk/rla;->OooO00o:Ljava/util/HashSet;

    return-void
.end method
