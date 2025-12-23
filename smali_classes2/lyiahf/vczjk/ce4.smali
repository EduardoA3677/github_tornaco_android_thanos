.class public final Llyiahf/vczjk/ce4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/j82;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/rd4;

.field public final OooOOO0:Llyiahf/vczjk/rd4;

.field public final OooOOOO:Llyiahf/vczjk/tm7;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/tm7;Llyiahf/vczjk/tc7;Llyiahf/vczjk/be4;Llyiahf/vczjk/i82;)V
    .locals 4

    const-string p4, "kotlinClass"

    invoke-static {p1, p4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p4, "packageProto"

    invoke-static {p2, p4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string p4, "nameResolver"

    invoke-static {p3, p4}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object p4, p1, Llyiahf/vczjk/tm7;->OooO00o:Ljava/lang/Class;

    invoke-static {p4}, Llyiahf/vczjk/rl7;->OooO00o(Ljava/lang/Class;)Llyiahf/vczjk/hy0;

    move-result-object p4

    new-instance v0, Llyiahf/vczjk/rd4;

    invoke-static {p4}, Llyiahf/vczjk/rd4;->OooO0o0(Llyiahf/vczjk/hy0;)Ljava/lang/String;

    move-result-object p4

    invoke-direct {v0, p4}, Llyiahf/vczjk/rd4;-><init>(Ljava/lang/String;)V

    iget-object p4, p1, Llyiahf/vczjk/tm7;->OooO0O0:Llyiahf/vczjk/fq3;

    sget-object v1, Llyiahf/vczjk/ik4;->OooOo00:Llyiahf/vczjk/ik4;

    iget-object v2, p4, Llyiahf/vczjk/fq3;->OooO0OO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ik4;

    const/4 v3, 0x0

    if-ne v2, v1, :cond_0

    iget-object p4, p4, Llyiahf/vczjk/fq3;->OooO0oo:Ljava/lang/Object;

    check-cast p4, Ljava/lang/String;

    goto :goto_0

    :cond_0
    move-object p4, v3

    :goto_0
    if-eqz p4, :cond_1

    invoke-virtual {p4}, Ljava/lang/String;->length()I

    move-result v1

    if-lez v1, :cond_1

    invoke-static {p4}, Llyiahf/vczjk/rd4;->OooO0OO(Ljava/lang/String;)Llyiahf/vczjk/rd4;

    move-result-object v3

    :cond_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/ce4;->OooOOO0:Llyiahf/vczjk/rd4;

    iput-object v3, p0, Llyiahf/vczjk/ce4;->OooOOO:Llyiahf/vczjk/rd4;

    iput-object p1, p0, Llyiahf/vczjk/ce4;->OooOOOO:Llyiahf/vczjk/tm7;

    sget-object p1, Llyiahf/vczjk/ue4;->OooOOO0:Llyiahf/vczjk/ug3;

    const-string p4, "packageModuleName"

    invoke-static {p1, p4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {p2, p1}, Llyiahf/vczjk/tn6;->OooOOO(Llyiahf/vczjk/sg3;Llyiahf/vczjk/ug3;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Integer;

    if-eqz p1, :cond_2

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    invoke-virtual {p3, p1}, Llyiahf/vczjk/be4;->Oooo(I)Ljava/lang/String;

    :cond_2
    return-void
.end method


# virtual methods
.method public final OooO00o()Llyiahf/vczjk/hy0;
    .locals 7

    new-instance v0, Llyiahf/vczjk/hy0;

    iget-object v1, p0, Llyiahf/vczjk/ce4;->OooOOO0:Llyiahf/vczjk/rd4;

    iget-object v2, v1, Llyiahf/vczjk/rd4;->OooO00o:Ljava/lang/String;

    const-string v3, "/"

    invoke-virtual {v2, v3}, Ljava/lang/String;->lastIndexOf(Ljava/lang/String;)I

    move-result v3

    const/4 v4, -0x1

    const/16 v5, 0x2f

    if-ne v3, v4, :cond_1

    sget-object v2, Llyiahf/vczjk/hc3;->OooO0OO:Llyiahf/vczjk/hc3;

    if-eqz v2, :cond_0

    goto :goto_0

    :cond_0
    const/16 v0, 0x9

    invoke-static {v0}, Llyiahf/vczjk/rd4;->OooO00o(I)V

    const/4 v0, 0x0

    throw v0

    :cond_1
    new-instance v4, Llyiahf/vczjk/hc3;

    const/4 v6, 0x0

    invoke-virtual {v2, v6, v3}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    move-result-object v2

    const/16 v3, 0x2e

    invoke-virtual {v2, v5, v3}, Ljava/lang/String;->replace(CC)Ljava/lang/String;

    move-result-object v2

    invoke-direct {v4, v2}, Llyiahf/vczjk/hc3;-><init>(Ljava/lang/String;)V

    move-object v2, v4

    :goto_0
    invoke-virtual {v1}, Llyiahf/vczjk/rd4;->OooO0Oo()Ljava/lang/String;

    move-result-object v1

    const-string v3, "getInternalName(...)"

    invoke-static {v1, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-static {v5, v1, v1}, Llyiahf/vczjk/z69;->OoooooO(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/qt5;->OooO0o0(Ljava/lang/String;)Llyiahf/vczjk/qt5;

    move-result-object v1

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/hy0;-><init>(Llyiahf/vczjk/hc3;Llyiahf/vczjk/qt5;)V

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    const-class v1, Llyiahf/vczjk/ce4;

    invoke-virtual {v1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ": "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/ce4;->OooOOO0:Llyiahf/vczjk/rd4;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
