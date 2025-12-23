.class public final synthetic Llyiahf/vczjk/rx7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOO0:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOOO:I

.field public final synthetic OooOOOo:Ljava/lang/String;

.field public final synthetic OooOOo:Ljava/lang/String;

.field public final synthetic OooOOo0:I

.field public final synthetic OooOOoo:Llyiahf/vczjk/pb7;

.field public final synthetic OooOo00:Llyiahf/vczjk/oe3;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;ILjava/lang/String;ILjava/lang/String;Llyiahf/vczjk/pb7;Llyiahf/vczjk/oe3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/rx7;->OooOOO0:Llyiahf/vczjk/oe3;

    iput-object p2, p0, Llyiahf/vczjk/rx7;->OooOOO:Llyiahf/vczjk/oe3;

    iput p3, p0, Llyiahf/vczjk/rx7;->OooOOOO:I

    iput-object p4, p0, Llyiahf/vczjk/rx7;->OooOOOo:Ljava/lang/String;

    iput p5, p0, Llyiahf/vczjk/rx7;->OooOOo0:I

    iput-object p6, p0, Llyiahf/vczjk/rx7;->OooOOo:Ljava/lang/String;

    iput-object p7, p0, Llyiahf/vczjk/rx7;->OooOOoo:Llyiahf/vczjk/pb7;

    iput-object p8, p0, Llyiahf/vczjk/rx7;->OooOo00:Llyiahf/vczjk/oe3;

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/nw7;

    const-string v0, "it"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/rx7;->OooOOO0:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/rx7;->OooOOO:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    goto :goto_0

    :cond_0
    const/4 p1, 0x0

    iget v0, p0, Llyiahf/vczjk/rx7;->OooOOOO:I

    iget-object v1, p0, Llyiahf/vczjk/rx7;->OooOOOo:Ljava/lang/String;

    iget v2, p0, Llyiahf/vczjk/rx7;->OooOOo0:I

    iget-object v3, p0, Llyiahf/vczjk/rx7;->OooOOo:Ljava/lang/String;

    invoke-static {v0, v2, v1, v3, p1}, Llyiahf/vczjk/px7;->OooO00o(IILjava/lang/String;Ljava/lang/String;Z)Lgithub/tornaco/android/thanos/db/profile/RuleRecord;

    move-result-object p1

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/db/profile/RuleRecord;->toString()Ljava/lang/String;

    iget-object v0, p0, Llyiahf/vczjk/rx7;->OooOOoo:Llyiahf/vczjk/pb7;

    invoke-virtual {v0}, Llyiahf/vczjk/pb7;->OooOOOO()Lgithub/tornaco/android/thanos/db/profile/RuleDb;

    move-result-object v1

    invoke-virtual {v1}, Lgithub/tornaco/android/thanos/db/profile/RuleDb;->ruleDao()Lgithub/tornaco/android/thanos/db/profile/RuleDao;

    move-result-object v1

    invoke-interface {v1, p1}, Lgithub/tornaco/android/thanos/db/profile/RuleDao;->insert(Lgithub/tornaco/android/thanos/db/profile/RuleRecord;)J

    move-result-wide v1

    invoke-virtual {v0}, Llyiahf/vczjk/pb7;->OooOo()V

    long-to-int p1, v1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/rx7;->OooOo00:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :goto_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
