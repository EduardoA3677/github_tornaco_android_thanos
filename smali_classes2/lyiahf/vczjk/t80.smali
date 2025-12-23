.class public final Llyiahf/vczjk/t80;
.super Ljava/util/IdentityHashMap;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = -0x4d627f4e9b8f4d0eL


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/u80;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/u80;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/t80;->this$0:Llyiahf/vczjk/u80;

    invoke-direct {p0}, Ljava/util/IdentityHashMap;-><init>()V

    return-void
.end method


# virtual methods
.method public final put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p2, Llyiahf/vczjk/i16;

    new-instance v0, Llyiahf/vczjk/g7;

    iget-object v1, p2, Llyiahf/vczjk/i16;->OooO00o:Llyiahf/vczjk/ye9;

    iget-object v2, p2, Llyiahf/vczjk/i16;->OooO0OO:Llyiahf/vczjk/mc5;

    iget-object p2, p2, Llyiahf/vczjk/i16;->OooO0O0:Llyiahf/vczjk/mc5;

    invoke-direct {v0, v1, p2, v2}, Llyiahf/vczjk/i16;-><init>(Llyiahf/vczjk/ye9;Llyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;)V

    invoke-super {p0, p1, v0}, Ljava/util/IdentityHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/i16;

    return-object p1
.end method
