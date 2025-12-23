.class public final Llyiahf/vczjk/oh7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $address:Llyiahf/vczjk/o1;

.field final synthetic $certificatePinner:Llyiahf/vczjk/yr0;

.field final synthetic $unverifiedHandshake:Llyiahf/vczjk/fm3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yr0;Llyiahf/vczjk/fm3;Llyiahf/vczjk/o1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/oh7;->$certificatePinner:Llyiahf/vczjk/yr0;

    iput-object p2, p0, Llyiahf/vczjk/oh7;->$unverifiedHandshake:Llyiahf/vczjk/fm3;

    iput-object p3, p0, Llyiahf/vczjk/oh7;->$address:Llyiahf/vczjk/o1;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/oh7;->$certificatePinner:Llyiahf/vczjk/yr0;

    iget-object v0, v0, Llyiahf/vczjk/yr0;->OooO0O0:Llyiahf/vczjk/zsa;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v1, p0, Llyiahf/vczjk/oh7;->$unverifiedHandshake:Llyiahf/vczjk/fm3;

    invoke-virtual {v1}, Llyiahf/vczjk/fm3;->OooO00o()Ljava/util/List;

    move-result-object v1

    iget-object v2, p0, Llyiahf/vczjk/oh7;->$address:Llyiahf/vczjk/o1;

    iget-object v2, v2, Llyiahf/vczjk/o1;->OooO0oo:Llyiahf/vczjk/lr3;

    iget-object v2, v2, Llyiahf/vczjk/lr3;->OooO0Oo:Ljava/lang/String;

    invoke-virtual {v0, v2, v1}, Llyiahf/vczjk/zsa;->OooOooO(Ljava/lang/String;Ljava/util/List;)Ljava/util/List;

    move-result-object v0

    return-object v0
.end method
