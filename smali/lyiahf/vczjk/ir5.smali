.class public final Llyiahf/vczjk/ir5;
.super Llyiahf/vczjk/os1;
.source "SourceFile"


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    sget-object p1, Llyiahf/vczjk/ms1;->OooO0O0:Llyiahf/vczjk/ms1;

    invoke-direct {p0, p1}, Llyiahf/vczjk/ir5;-><init>(Llyiahf/vczjk/os1;)V

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/os1;)V
    .locals 1

    const-string v0, "initialExtras"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p1, p1, Llyiahf/vczjk/os1;->OooO00o:Ljava/util/LinkedHashMap;

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Llyiahf/vczjk/os1;-><init>()V

    iget-object v0, p0, Llyiahf/vczjk/os1;->OooO00o:Ljava/util/LinkedHashMap;

    invoke-interface {v0, p1}, Ljava/util/Map;->putAll(Ljava/util/Map;)V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/ns1;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/os1;->OooO00o:Ljava/util/LinkedHashMap;

    invoke-virtual {v0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
