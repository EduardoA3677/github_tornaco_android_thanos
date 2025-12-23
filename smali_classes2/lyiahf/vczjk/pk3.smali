.class public final Llyiahf/vczjk/pk3;
.super Llyiahf/vczjk/dp1;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/nk3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/nk3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/pk3;->OooO00o:Llyiahf/vczjk/nk3;

    return-void
.end method

.method public static OooO0OO()Llyiahf/vczjk/pk3;
    .locals 2

    new-instance v0, Llyiahf/vczjk/nk3;

    invoke-direct {v0}, Llyiahf/vczjk/nk3;-><init>()V

    new-instance v1, Llyiahf/vczjk/pk3;

    invoke-direct {v1, v0}, Llyiahf/vczjk/pk3;-><init>(Llyiahf/vczjk/nk3;)V

    return-object v1
.end method


# virtual methods
.method public final OooO00o(Ljava/lang/reflect/Type;)Llyiahf/vczjk/fp1;
    .locals 2

    invoke-static {p1}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/reflect/Type;)Lcom/google/gson/reflect/TypeToken;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/pk3;->OooO00o:Llyiahf/vczjk/nk3;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/nk3;->OooO0o0(Lcom/google/gson/reflect/TypeToken;)Llyiahf/vczjk/r1a;

    move-result-object p1

    new-instance v1, Llyiahf/vczjk/qk3;

    invoke-direct {v1, v0, p1}, Llyiahf/vczjk/qk3;-><init>(Llyiahf/vczjk/nk3;Llyiahf/vczjk/r1a;)V

    return-object v1
.end method

.method public final OooO0O0(Ljava/lang/reflect/Type;[Ljava/lang/annotation/Annotation;Llyiahf/vczjk/mi;)Llyiahf/vczjk/fp1;
    .locals 0

    invoke-static {p1}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/reflect/Type;)Lcom/google/gson/reflect/TypeToken;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/pk3;->OooO00o:Llyiahf/vczjk/nk3;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/nk3;->OooO0o0(Lcom/google/gson/reflect/TypeToken;)Llyiahf/vczjk/r1a;

    move-result-object p1

    new-instance p3, Llyiahf/vczjk/tqa;

    invoke-direct {p3, p2, p1}, Llyiahf/vczjk/tqa;-><init>(Llyiahf/vczjk/nk3;Llyiahf/vczjk/r1a;)V

    return-object p3
.end method
