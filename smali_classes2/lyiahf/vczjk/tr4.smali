.class public final Llyiahf/vczjk/tr4;
.super Llyiahf/vczjk/ih6;
.source "SourceFile"


# static fields
.field public static final synthetic OooOoo0:[Llyiahf/vczjk/th4;


# instance fields
.field public final OooOo:Llyiahf/vczjk/o45;

.field public final OooOo0O:Llyiahf/vczjk/mm7;

.field public final OooOo0o:Llyiahf/vczjk/ld9;

.field public final OooOoO:Llyiahf/vczjk/j45;

.field public final OooOoO0:Llyiahf/vczjk/de4;

.field public final OooOoOO:Llyiahf/vczjk/ko;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/za7;

    const-class v1, Llyiahf/vczjk/tr4;

    const-string v2, "binaryClasses"

    const-string v3, "getBinaryClasses$descriptors_jvm()Ljava/util/Map;"

    const/4 v4, 0x0

    invoke-direct {v0, v1, v2, v3, v4}, Llyiahf/vczjk/za7;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sget-object v2, Llyiahf/vczjk/ym7;->OooO00o:Llyiahf/vczjk/zm7;

    invoke-virtual {v2, v0}, Llyiahf/vczjk/zm7;->OooO0oO(Llyiahf/vczjk/za7;)Llyiahf/vczjk/mh4;

    move-result-object v0

    const-string v3, "partToFacade"

    const-string v5, "getPartToFacade()Ljava/util/HashMap;"

    invoke-static {v1, v3, v5, v4, v2}, Llyiahf/vczjk/u81;->OooOOOo(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;ILlyiahf/vczjk/zm7;)Llyiahf/vczjk/mh4;

    move-result-object v1

    const/4 v2, 0x2

    new-array v2, v2, [Llyiahf/vczjk/th4;

    aput-object v0, v2, v4

    const/4 v0, 0x1

    aput-object v1, v2, v0

    sput-object v2, Llyiahf/vczjk/tr4;->OooOoo0:[Llyiahf/vczjk/th4;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/mm7;)V
    .locals 4

    const-string v0, "outerContext"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v1, p2, Llyiahf/vczjk/mm7;->OooO00o:Llyiahf/vczjk/hc3;

    iget-object v2, v0, Llyiahf/vczjk/s64;->OooOOOO:Llyiahf/vczjk/dm5;

    invoke-direct {p0, v2, v1}, Llyiahf/vczjk/ih6;-><init>(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hc3;)V

    iput-object p2, p0, Llyiahf/vczjk/tr4;->OooOo0O:Llyiahf/vczjk/mm7;

    const/4 v1, 0x6

    const/4 v2, 0x0

    invoke-static {p1, p0, v2, v1}, Llyiahf/vczjk/l4a;->OooOOO0(Llyiahf/vczjk/ld9;Llyiahf/vczjk/py0;Llyiahf/vczjk/cm7;I)Llyiahf/vczjk/ld9;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/tr4;->OooOo0o:Llyiahf/vczjk/ld9;

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooO0Oo:Llyiahf/vczjk/l82;

    invoke-virtual {v0}, Llyiahf/vczjk/l82;->OooO0OO()Llyiahf/vczjk/s72;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/s72;->OooO0OO:Llyiahf/vczjk/pp3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v0, Llyiahf/vczjk/yi5;->OooO0oO:Llyiahf/vczjk/yi5;

    iget-object v0, p1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/s64;

    iget-object v1, v0, Llyiahf/vczjk/s64;->OooO00o:Llyiahf/vczjk/q45;

    new-instance v2, Llyiahf/vczjk/sr4;

    const/4 v3, 0x0

    invoke-direct {v2, p0, v3}, Llyiahf/vczjk/sr4;-><init>(Llyiahf/vczjk/tr4;I)V

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v3, Llyiahf/vczjk/o45;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/n45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v3, p0, Llyiahf/vczjk/tr4;->OooOo:Llyiahf/vczjk/o45;

    new-instance v2, Llyiahf/vczjk/de4;

    invoke-direct {v2, p1, p2, p0}, Llyiahf/vczjk/de4;-><init>(Llyiahf/vczjk/ld9;Llyiahf/vczjk/mm7;Llyiahf/vczjk/tr4;)V

    iput-object v2, p0, Llyiahf/vczjk/tr4;->OooOoO0:Llyiahf/vczjk/de4;

    new-instance v2, Llyiahf/vczjk/sr4;

    const/4 v3, 0x1

    invoke-direct {v2, p0, v3}, Llyiahf/vczjk/sr4;-><init>(Llyiahf/vczjk/tr4;I)V

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v3, Llyiahf/vczjk/j45;

    invoke-direct {v3, v1, v2}, Llyiahf/vczjk/o45;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/le3;)V

    iput-object v3, p0, Llyiahf/vczjk/tr4;->OooOoO:Llyiahf/vczjk/j45;

    iget-object v0, v0, Llyiahf/vczjk/s64;->OooOo0O:Llyiahf/vczjk/c74;

    iget-boolean v0, v0, Llyiahf/vczjk/c74;->OooO0O0:Z

    if-eqz v0, :cond_0

    sget-object p1, Llyiahf/vczjk/qp3;->OooOOO0:Llyiahf/vczjk/jo;

    goto :goto_0

    :cond_0
    invoke-static {p1, p2}, Llyiahf/vczjk/dn8;->o00oO0o(Llyiahf/vczjk/ld9;Llyiahf/vczjk/b64;)Llyiahf/vczjk/lr4;

    move-result-object p1

    :goto_0
    iput-object p1, p0, Llyiahf/vczjk/tr4;->OooOoOO:Llyiahf/vczjk/ko;

    new-instance p1, Llyiahf/vczjk/sr4;

    const/4 p2, 0x2

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/sr4;-><init>(Llyiahf/vczjk/tr4;I)V

    invoke-virtual {v1, p1}, Llyiahf/vczjk/q45;->OooO00o(Llyiahf/vczjk/le3;)Llyiahf/vczjk/o45;

    return-void
.end method


# virtual methods
.method public final OooO0oO()Llyiahf/vczjk/sx8;
    .locals 1

    new-instance v0, Llyiahf/vczjk/sw7;

    invoke-direct {v0, p0}, Llyiahf/vczjk/sw7;-><init>(Llyiahf/vczjk/tr4;)V

    return-object v0
.end method

.method public final OooOOo0()Llyiahf/vczjk/ko;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tr4;->OooOoOO:Llyiahf/vczjk/ko;

    return-object v0
.end method

.method public final OoooOO0()Llyiahf/vczjk/jg5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/tr4;->OooOoO0:Llyiahf/vczjk/de4;

    return-object v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Lazy Java package fragment: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/ih6;->OooOo00:Llyiahf/vczjk/hc3;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " of module "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/tr4;->OooOo0o:Llyiahf/vczjk/ld9;

    iget-object v1, v1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/s64;

    iget-object v1, v1, Llyiahf/vczjk/s64;->OooOOOO:Llyiahf/vczjk/dm5;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
