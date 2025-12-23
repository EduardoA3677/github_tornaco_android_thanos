.class public final Llyiahf/vczjk/he2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $event$inlined:Llyiahf/vczjk/de2;

.field final synthetic $match:Llyiahf/vczjk/hl7;

.field final synthetic this$0:Llyiahf/vczjk/ie2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hl7;Llyiahf/vczjk/ie2;Llyiahf/vczjk/de2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/he2;->$match:Llyiahf/vczjk/hl7;

    iput-object p2, p0, Llyiahf/vczjk/he2;->this$0:Llyiahf/vczjk/ie2;

    iput-object p3, p0, Llyiahf/vczjk/he2;->$event$inlined:Llyiahf/vczjk/de2;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/c0a;

    move-object v0, p1

    check-cast v0, Llyiahf/vczjk/ie2;

    iget-object v1, p0, Llyiahf/vczjk/he2;->this$0:Llyiahf/vczjk/ie2;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/xa;

    invoke-virtual {v1}, Llyiahf/vczjk/xa;->getDragAndDropManager()Llyiahf/vczjk/ee2;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/zc;

    iget-object v1, v1, Llyiahf/vczjk/zc;->OooO0O0:Llyiahf/vczjk/ny;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/ny;->contains(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/he2;->$event$inlined:Llyiahf/vczjk/de2;

    invoke-static {v1}, Llyiahf/vczjk/yi4;->OoooOOO(Llyiahf/vczjk/de2;)J

    move-result-wide v1

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/mc4;->OooOOO(Llyiahf/vczjk/ie2;J)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/he2;->$match:Llyiahf/vczjk/hl7;

    iput-object p1, v0, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/b0a;->OooOOOO:Llyiahf/vczjk/b0a;

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/b0a;->OooOOO0:Llyiahf/vczjk/b0a;

    return-object p1
.end method
