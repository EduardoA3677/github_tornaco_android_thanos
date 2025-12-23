.class public final Llyiahf/vczjk/ei1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/mr1;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/xj0;


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/oz6;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/xj0;

    const/16 v1, 0xe

    invoke-direct {v0, v1}, Llyiahf/vczjk/xj0;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/ei1;->OooOOO:Llyiahf/vczjk/xj0;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/oz6;)V
    .locals 1

    const-string v0, "connectionWrapper"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ei1;->OooOOO0:Llyiahf/vczjk/oz6;

    return-void
.end method


# virtual methods
.method public final OooOOOO(Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->Oooo000(Llyiahf/vczjk/mr1;Llyiahf/vczjk/or1;)Llyiahf/vczjk/or1;

    move-result-object p1

    return-object p1
.end method

.method public final OooOo(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->OooOoOO(Llyiahf/vczjk/mr1;Llyiahf/vczjk/nr1;)Llyiahf/vczjk/mr1;

    move-result-object p1

    return-object p1
.end method

.method public final OooOoO(Llyiahf/vczjk/nr1;)Llyiahf/vczjk/or1;
    .locals 0

    invoke-static {p0, p1}, Llyiahf/vczjk/tg0;->OooOooO(Llyiahf/vczjk/mr1;Llyiahf/vczjk/nr1;)Llyiahf/vczjk/or1;

    move-result-object p1

    return-object p1
.end method

.method public final getKey()Llyiahf/vczjk/nr1;
    .locals 1

    sget-object v0, Llyiahf/vczjk/ei1;->OooOOO:Llyiahf/vczjk/xj0;

    return-object v0
.end method

.method public final o000OOo(Ljava/lang/Object;Llyiahf/vczjk/ze3;)Ljava/lang/Object;
    .locals 0

    invoke-interface {p2, p1, p0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method
